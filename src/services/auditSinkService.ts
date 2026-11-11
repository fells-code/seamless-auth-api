/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type {
  AuditSinkSettings,
  CalloutTestResponse,
  CreateAuditSinkRequest,
  UpdateAuditSinkRequest,
} from '@seamless-auth/types';
import { Op, QueryTypes } from 'sequelize';

import {
  eventRecord,
  sendToSink,
  sinkDestinationProblem,
  testRecord,
} from '../lib/auditSinkTransport.js';
import { AuditSink } from '../models/auditSinks.js';
import { getSequelize } from '../models/index.js';
import getLogger from '../utils/logger.js';
import { readExportBatch } from './auditExport.js';

const logger = getLogger('audit-sinks');

export class AuditSinkError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'AuditSinkError';
  }
}

export const SINK_BATCH = 100;
const MAX_BACKOFF_MS = 60_000;
// Taken with each sink's id as the second key, so replicas take turns per sink and two sinks
// never wait on each other. The two-key form is a separate space from the single-key locks the
// webhook dispatcher and audit maintenance take.
const SINK_LOCK_CLASS = 72_641_003;

function now() {
  return new Date();
}

type ChainBounds = { head: number; oldest: number | null };

async function chainBounds(): Promise<ChainBounds> {
  const [row] = await getSequelize().query<{ head: string | null; oldest: string | null }>(
    `SELECT (SELECT seq FROM public.auth_event_chain_head WHERE id = 1) AS head,
            (SELECT min(seq) FROM public.auth_events) AS oldest`,
    { type: QueryTypes.SELECT },
  );
  return {
    head: row?.head == null ? 0 : Number(row.head),
    oldest: row?.oldest == null ? null : Number(row.oldest),
  };
}

export async function chainHead(): Promise<number> {
  return (await chainBounds()).head;
}

export function serializeSink(sink: AuditSink, head: number) {
  const cursorSeq = Number(sink.cursorSeq);
  return {
    id: sink.id,
    name: sink.name,
    enabled: sink.enabled,
    settings: sink.settings,
    status: {
      cursorSeq,
      lagEvents: Math.max(0, head - cursorSeq),
      lastDeliveredAt: sink.lastDeliveredAt?.toISOString() ?? null,
      lastFailure: sink.lastFailure ?? null,
      lastFailureAt: sink.lastFailureAt?.toISOString() ?? null,
    },
    createdAt: sink.createdAt.toISOString(),
    updatedAt: sink.updatedAt.toISOString(),
  };
}

function assertSettings(settings: AuditSinkSettings) {
  const problem = sinkDestinationProblem(settings);
  if (problem) throw new AuditSinkError(400, problem);
}

export async function listSinks() {
  return AuditSink.findAll({ order: [['createdAt', 'ASC']] });
}

export async function getSink(id: string) {
  const sink = await AuditSink.findByPk(id);
  if (!sink) throw new AuditSinkError(404, 'Audit sink not found');
  return sink;
}

/**
 * Without `startAfterSeq` the sink starts after the newest event. A replay may not start before
 * the oldest event still held, since what retention archived cannot be streamed.
 */
async function startingCursor(startAfterSeq: number | undefined) {
  const { head, oldest } = await chainBounds();
  if (startAfterSeq === undefined) return head;

  if (startAfterSeq > head) {
    throw new AuditSinkError(400, `startAfterSeq is past the newest event (${head})`);
  }
  if (oldest !== null && startAfterSeq < oldest - 1) {
    throw new AuditSinkError(
      400,
      `startAfterSeq is before the oldest event still held (${oldest}); older events are in the retention archive`,
    );
  }
  return startAfterSeq;
}

export async function createSink(input: CreateAuditSinkRequest, actorUserId: string | null) {
  assertSettings(input.settings);
  const cursorSeq = await startingCursor(input.startAfterSeq);

  return AuditSink.create({
    name: input.name,
    kind: input.settings.kind,
    settings: input.settings,
    enabled: input.enabled ?? true,
    cursorSeq: String(cursorSeq),
    createdBy: actorUserId,
  });
}

/** A change of settings or a re-enable is tried at once rather than after the backoff. */
export async function updateSink(id: string, input: UpdateAuditSinkRequest) {
  const sink = await getSink(id);
  if (input.settings !== undefined) assertSettings(input.settings);

  await sink.update({
    ...(input.name !== undefined ? { name: input.name } : {}),
    ...(input.settings !== undefined
      ? { settings: input.settings, kind: input.settings.kind }
      : {}),
    ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
    failureCount: 0,
    nextAttemptAt: null,
  });

  return sink;
}

export async function deleteSink(id: string) {
  const sink = await getSink(id);
  await sink.destroy();
  return sink;
}

/** One record marked as a test, outside the chain. It moves no cursor and records no failure. */
export async function sendSinkTest(id: string): Promise<CalloutTestResponse> {
  const sink = await getSink(id);
  return sendToSink(sink.settings, [testRecord(sink.id)]);
}

/** Doubles from one second, capped at a minute, with up to 10% taken off so sinks spread out. */
export function backoffMs(failures: number) {
  const base = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.max(0, failures - 1));
  return Math.round(base * (1 - Math.random() * 0.1));
}

/**
 * Sends the next batch past the sink's cursor and moves the cursor only when the destination
 * took all of it, so an event is never skipped: a failure resends the same batch later. Rows are
 * read by `seq` and committed rows form a gapless prefix of it (see `dispatchWebhooks`).
 *
 * The send happens inside the transaction holding the sink's lock, so a replica never sends a
 * batch another is sending. If the commit fails after a send, the batch goes again: delivery is
 * at least once, and `seq` lets the destination drop a repeat.
 *
 * Returns how many events were delivered.
 */
export async function deliverSink(id: string): Promise<number> {
  const sequelize = getSequelize();

  return sequelize.transaction(async (transaction) => {
    const [{ locked }] = await sequelize.query<{ locked: boolean }>(
      'SELECT pg_try_advisory_xact_lock(:lockClass, hashtext(:id)) AS locked',
      {
        replacements: { lockClass: SINK_LOCK_CLASS, id },
        type: QueryTypes.SELECT,
        transaction,
      },
    );
    if (!locked) return 0;

    const sink = await AuditSink.findByPk(id, { transaction });
    if (!sink || !sink.enabled) return 0;
    if (sink.nextAttemptAt && sink.nextAttemptAt > now()) return 0;

    const events = await readExportBatch({
      afterSeq: Number(sink.cursorSeq),
      maxSeq: Number.MAX_SAFE_INTEGER,
      limit: SINK_BATCH,
      sequelize,
      transaction,
    });
    if (events.length === 0) return 0;

    const attempt = await sendToSink(sink.settings, events.map(eventRecord));

    if (attempt.ok) {
      await sink.update(
        {
          cursorSeq: String(events[events.length - 1].seq),
          lastDeliveredAt: now(),
          failureCount: 0,
          nextAttemptAt: null,
        },
        { transaction },
      );
      return events.length;
    }

    // Not audited: a sink that is down would write an event per retry into the very chain it
    // streams.
    const failureCount = sink.failureCount + 1;
    await sink.update(
      {
        lastFailure: attempt.failure,
        lastFailureAt: now(),
        failureCount,
        nextAttemptAt: new Date(Date.now() + backoffMs(failureCount)),
      },
      { transaction },
    );
    return 0;
  });
}

// Bounds one sink's catch-up within a tick to 5,000 events, so a long backlog does not hold
// the loop from sinks that become due meanwhile.
const MAX_BATCHES_PER_TICK = 50;

async function drainSink(id: string) {
  try {
    for (let batch = 0; batch < MAX_BATCHES_PER_TICK; batch += 1) {
      if ((await deliverSink(id)) < SINK_BATCH) return;
    }
  } catch (error) {
    logger.error(`Audit sink ${id} failed: ${(error as Error).message}`);
  }
}

/** One pass over every enabled sink that is due. Errors are logged, not thrown. */
export async function runAuditSinkTick() {
  try {
    const sinks = await AuditSink.findAll({
      attributes: ['id'],
      where: {
        enabled: true,
        [Op.or]: [{ nextAttemptAt: null }, { nextAttemptAt: { [Op.lte]: now() } }],
      },
    });
    await Promise.all(sinks.map((sink) => drainSink(sink.id)));
  } catch (error) {
    logger.error(`Audit sink tick failed: ${(error as Error).message}`);
  }
}

const TICK_MS = 1000;

/** Polls once a second, like webhook delivery. Idle, it is one read of a small table. */
export function startAuditSinkDelivery() {
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    void runAuditSinkTick().finally(() => {
      running = false;
    });
  }, TICK_MS);
  timer.unref();
  return timer;
}
