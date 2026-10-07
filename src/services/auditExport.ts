/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes, Sequelize, Transaction } from 'sequelize';

import { getSequelize } from '../models/index.js';

/**
 * The format both the bulk export and the retention archive write: newline-delimited
 * JSON, one line per event in chain order, then a manifest line last. The manifest
 * trails because its count and last hash are only known once the events are written,
 * and an export is streamed rather than buffered.
 *
 * Each event carries `payload`, the exact canonical text the database hashed. An auditor
 * verifies the file without the database by checking, line by line, that
 * `sha256(prevHash + payload) == hash` and that each `prevHash` is the previous line's
 * `hash`. The first `prevHash` is the manifest's `anchorHash`.
 */
export const AUDIT_EXPORT_FORMAT = 'seamless-auth-events/1';

export const EXPORT_BATCH_SIZE = 5000;

export interface ExportedAuthEvent {
  seq: number;
  id: string;
  createdAt: string;
  type: string;
  userId: string | null;
  actorUserId: string | null;
  sessionId: string | null;
  attemptId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  deploymentId: string | null;
  deviceClass: string | null;
  mailProvider: string | null;
  owner: boolean | null;
  metadata: Record<string, unknown> | null;
  prevHash: string | null;
  hash: string;
  payload: string;
}

export interface AuditExportManifest {
  type: 'manifest';
  format: typeof AUDIT_EXPORT_FORMAT;
  generatedAt: string;
  reason: 'export' | 'retention';
  from: string | null;
  to: string | null;
  firstSeq: number | null;
  lastSeq: number | null;
  count: number;
  anchorHash: string | null;
  lastHash: string | null;
}

type ExportRow = {
  seq: string;
  id: string;
  created_at: Date;
  type: string;
  user_id: string | null;
  actor_user_id: string | null;
  session_id: string | null;
  attempt_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  deployment_id: string | null;
  device_class: string | null;
  mail_provider: string | null;
  owner: boolean | null;
  metadata: Record<string, unknown> | null;
  prev_hash: string | null;
  hash: string;
  payload: string;
};

export const EXPORT_COLUMNS = `
  e.seq, e.id, e.created_at, e.type, e.user_id, e.actor_user_id, e.session_id,
  e.attempt_id, e.ip_address, e.user_agent, e.deployment_id, e.device_class,
  e.mail_provider, e.owner, e.metadata, e.prev_hash, e.hash,
  public.auth_event_payload(e.*) AS payload
`;

export function toExportedEvent(row: ExportRow): ExportedAuthEvent {
  return {
    seq: Number(row.seq),
    id: row.id,
    createdAt: new Date(row.created_at).toISOString(),
    type: row.type,
    userId: row.user_id,
    actorUserId: row.actor_user_id,
    sessionId: row.session_id,
    attemptId: row.attempt_id,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    deploymentId: row.deployment_id,
    deviceClass: row.device_class,
    mailProvider: row.mail_provider,
    owner: row.owner,
    metadata: row.metadata,
    prevHash: row.prev_hash,
    hash: row.hash,
    payload: row.payload,
  };
}

/**
 * One batch of events after `afterSeq`, in chain order. Keyset rather than offset
 * pagination, so a period of any size is read in constant memory.
 */
export async function readExportBatch(params: {
  afterSeq: number;
  maxSeq: number;
  limit?: number;
  sequelize?: Sequelize;
  transaction?: Transaction;
}): Promise<ExportedAuthEvent[]> {
  const rows = await (params.sequelize ?? getSequelize()).query<ExportRow>(
    `SELECT ${EXPORT_COLUMNS}
       FROM public.auth_events e
      WHERE e.seq > :afterSeq AND e.seq <= :maxSeq
      ORDER BY e.seq
      LIMIT :limit`,
    {
      type: QueryTypes.SELECT,
      replacements: {
        afterSeq: params.afterSeq,
        maxSeq: params.maxSeq,
        limit: params.limit ?? EXPORT_BATCH_SIZE,
      },
      transaction: params.transaction,
    },
  );

  return rows.map(toExportedEvent);
}

type SeqBounds = { first_seq: string | null; last_seq: string | null };

/**
 * The contiguous run of the chain that covers `[from, to)`.
 *
 * A period is turned into a range of `seq` rather than filtered by `created_at` row by
 * row. Rows written by different replicas can be a little out of order in time, and a
 * filtered export would leave holes that make its own chain fail to verify. The range
 * includes such a row rather than dropping it, so an export can carry a few events
 * stamped just outside the period. The range is also pinned when the export starts, so
 * events written while it runs belong to the next one.
 */
async function resolveSeqBounds(from?: Date, to?: Date) {
  const [bounds] = await getSequelize().query<SeqBounds>(
    `SELECT
       (SELECT min(seq) FROM public.auth_events
         WHERE CAST(:from AS timestamptz) IS NULL OR created_at >= CAST(:from AS timestamptz)
       ) AS first_seq,
       (SELECT max(seq) FROM public.auth_events
         WHERE CAST(:to AS timestamptz) IS NULL OR created_at < CAST(:to AS timestamptz)
       ) AS last_seq`,
    {
      type: QueryTypes.SELECT,
      replacements: { from: from?.toISOString() ?? null, to: to?.toISOString() ?? null },
    },
  );

  const firstSeq = bounds.first_seq === null ? null : Number(bounds.first_seq);
  const lastSeq = bounds.last_seq === null ? null : Number(bounds.last_seq);

  if (firstSeq === null || lastSeq === null || firstSeq > lastSeq) return null;

  return { firstSeq, lastSeq };
}

/** Streams every event in `[from, to)` through `write`, then the manifest. */
export async function streamAuthEventExport(params: {
  from?: Date;
  to?: Date;
  write: (line: string) => Promise<void> | void;
}): Promise<AuditExportManifest> {
  const { from, to, write } = params;
  const bounds = await resolveSeqBounds(from, to);

  let afterSeq = bounds ? bounds.firstSeq - 1 : 0;
  let count = 0;
  let firstSeq: number | null = null;
  let lastSeq: number | null = null;
  let anchorHash: string | null = null;
  let lastHash: string | null = null;

  while (bounds) {
    const batch = await readExportBatch({ afterSeq, maxSeq: bounds.lastSeq });

    if (batch.length === 0) break;

    for (const event of batch) {
      if (firstSeq === null) {
        firstSeq = event.seq;
        anchorHash = event.prevHash;
      }
      await write(`${JSON.stringify(event)}\n`);
      lastSeq = event.seq;
      lastHash = event.hash;
      count += 1;
    }

    afterSeq = batch[batch.length - 1].seq;
  }

  const manifest = buildManifest({
    reason: 'export',
    from,
    to,
    firstSeq,
    lastSeq,
    count,
    anchorHash,
    lastHash,
  });

  await write(`${JSON.stringify(manifest)}\n`);

  return manifest;
}

export function buildManifest(
  fields: Omit<AuditExportManifest, 'type' | 'format' | 'generatedAt' | 'from' | 'to'> & {
    from?: Date;
    to?: Date;
  },
): AuditExportManifest {
  const { from, to, ...rest } = fields;

  return {
    type: 'manifest',
    format: AUDIT_EXPORT_FORMAT,
    generatedAt: new Date().toISOString(),
    from: from?.toISOString() ?? null,
    to: to?.toISOString() ?? null,
    ...rest,
  };
}
