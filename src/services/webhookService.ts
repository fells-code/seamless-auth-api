/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { randomUUID } from 'node:crypto';

import {
  type CalloutFailure,
  type CalloutTestResponse,
  type CreateWebhookEndpointRequest,
  type UpdateWebhookEndpointRequest,
  WEBHOOK_FAILING_DISABLE_SECONDS,
  WEBHOOK_PAYLOAD_VERSION,
  WEBHOOK_RETRY_SCHEDULE_SECONDS,
  WEBHOOK_SECRET_ROTATION_OVERLAP_SECONDS,
  WEBHOOK_TEST_EVENT_TYPE,
  WEBHOOK_TIMEOUT_MS,
  type WebhookDeliveryQuery,
  type WebhookDeliveryStatus,
  type WebhookEventType,
} from '@seamless-auth/types';
import { fn, Op, QueryTypes, type Transaction, type WhereOptions } from 'sequelize';

import { productionSecretMissing } from '../config/authSecrets.js';
import {
  calloutSigningSecrets,
  encryptCalloutSecret,
  generateCalloutSecret,
  signedCalloutHeaders,
} from '../lib/calloutSigning.js';
import { CalloutError, calloutRequest, calloutUrlProblem } from '../lib/calloutTransport.js';
import { getSequelize } from '../models/index.js';
import { User } from '../models/users.js';
import { WebhookDelivery, type WebhookDeliveryAttributes } from '../models/webhookDeliveries.js';
import { WebhookEndpoint } from '../models/webhookEndpoints.js';
import getLogger from '../utils/logger.js';
import { AuthEventService } from './authEventService.js';
import {
  type DispatchableAuthEvent,
  WEBHOOK_SOURCE_TYPES,
  webhookEventFor,
} from './webhookCatalog.js';

const logger = getLogger('webhooks');

export class WebhookError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'WebhookError';
  }
}

// A receiver only needs to say yes or no, so its body is read for the status alone.
const MAX_RESPONSE_BYTES = 64 * 1024;
const DISPATCH_BATCH = 500;
const DELIVERY_BATCH = 50;
const DELIVERY_RETENTION_DAYS = 30;
const CURSOR_NAME = 'webhooks';
// Distinct from the audit maintenance lock, so the two never wait on each other.
const DISPATCH_LOCK_KEY = 72_641_002;

function now() {
  return new Date();
}

function addSeconds(at: Date, seconds: number) {
  return new Date(at.getTime() + seconds * 1000);
}

export function serializeEndpoint(endpoint: WebhookEndpoint) {
  const rotating =
    endpoint.previousSecretExpiresAt && endpoint.previousSecretExpiresAt > now()
      ? endpoint.previousSecretExpiresAt.toISOString()
      : null;

  return {
    id: endpoint.id,
    url: endpoint.url,
    description: endpoint.description ?? null,
    eventTypes: endpoint.eventTypes,
    enabled: endpoint.enabled,
    disabledReason: endpoint.disabledReason ?? null,
    version: WEBHOOK_PAYLOAD_VERSION,
    previousSecretExpiresAt: rotating,
    createdAt: endpoint.createdAt.toISOString(),
    updatedAt: endpoint.updatedAt.toISOString(),
  };
}

export function serializeDelivery(delivery: WebhookDelivery) {
  return {
    id: delivery.id,
    endpointId: delivery.endpointId,
    eventType: delivery.eventType,
    status: delivery.status,
    attempts: delivery.attempts,
    nextAttemptAt: delivery.nextAttemptAt?.toISOString() ?? null,
    lastAttemptAt: delivery.lastAttemptAt?.toISOString() ?? null,
    lastStatusCode: delivery.lastStatusCode ?? null,
    lastFailure: delivery.lastFailure ?? null,
    createdAt: delivery.createdAt.toISOString(),
  };
}

function assertUrl(url: string) {
  const problem = calloutUrlProblem(url);
  if (problem) throw new WebhookError(400, `url ${problem}`);
}

function assertSecretKey() {
  if (productionSecretMissing('CALLOUT_SECRET_ENCRYPTION_KEY')) {
    throw new WebhookError(
      409,
      'CALLOUT_SECRET_ENCRYPTION_KEY must be set before a webhook can be created',
    );
  }
}

function secretColumns(secret: string) {
  const { ciphertext, iv, tag } = encryptCalloutSecret(secret);
  return { secretCiphertext: ciphertext, secretIv: iv, secretTag: tag };
}

export function signingSecrets(endpoint: WebhookEndpoint, at: Date = now()): string[] {
  return calloutSigningSecrets(endpoint, at);
}

export async function listEndpoints() {
  return WebhookEndpoint.findAll({ order: [['createdAt', 'ASC']] });
}

export async function getEndpoint(id: string) {
  const endpoint = await WebhookEndpoint.findByPk(id);
  if (!endpoint) throw new WebhookError(404, 'Webhook not found');
  return endpoint;
}

export async function createEndpoint(
  input: CreateWebhookEndpointRequest,
  actorUserId: string | null,
) {
  assertUrl(input.url);
  assertSecretKey();

  const secret = generateCalloutSecret();
  const endpoint = await WebhookEndpoint.create({
    url: input.url,
    description: input.description ?? null,
    eventTypes: input.eventTypes,
    enabled: input.enabled ?? true,
    createdBy: actorUserId,
    ...secretColumns(secret),
  });

  return { endpoint, secret };
}

export async function updateEndpoint(id: string, input: UpdateWebhookEndpointRequest) {
  const endpoint = await getEndpoint(id);
  if (input.url !== undefined) assertUrl(input.url);
  const reenabling = input.enabled === true && !endpoint.enabled;

  await endpoint.update({
    ...(input.url !== undefined ? { url: input.url } : {}),
    ...(input.description !== undefined ? { description: input.description } : {}),
    ...(input.eventTypes !== undefined ? { eventTypes: input.eventTypes } : {}),
    ...(input.enabled !== undefined
      ? {
          enabled: input.enabled,
          disabledReason: input.enabled ? null : 'manual',
          failingSince: null,
        }
      : {}),
  });

  // Releases what was held while it was off. Deliveries are pruned after 30 days, so that is how
  // far back a catch-up reaches. A dead delivery stays dead; redeliver sends it.
  const released = reenabling
    ? (
        await WebhookDelivery.update(
          // The database's clock, which the due check compares against, so a skewed app clock
          // cannot leave released deliveries not yet due.
          { nextAttemptAt: fn('now') as unknown as Date },
          {
            where: {
              endpointId: endpoint.id,
              status: { [Op.in]: ['pending', 'failed'] },
              nextAttemptAt: null,
            },
          },
        )
      )[0]
    : 0;

  return { endpoint, released };
}

export async function deleteEndpoint(id: string) {
  const endpoint = await getEndpoint(id);
  await endpoint.destroy();
  return endpoint;
}

/**
 * The old secret keeps signing for a day beside the new one, so receivers move over without a
 * dropped delivery. Rotating again within that day ends the old secret's overlap early: only two
 * secrets ever sign.
 */
export async function rotateEndpointSecret(id: string) {
  assertSecretKey();
  const endpoint = await getEndpoint(id);
  const secret = generateCalloutSecret();
  const previousSecretExpiresAt = addSeconds(now(), WEBHOOK_SECRET_ROTATION_OVERLAP_SECONDS);

  await endpoint.update({
    previousSecretCiphertext: endpoint.secretCiphertext,
    previousSecretIv: endpoint.secretIv,
    previousSecretTag: endpoint.secretTag,
    previousSecretExpiresAt,
    ...secretColumns(secret),
  });

  return { endpoint, secret, previousSecretExpiresAt };
}

function body(id: string, type: string, timestamp: Date, data: unknown) {
  return JSON.stringify({
    id,
    type,
    version: WEBHOOK_PAYLOAD_VERSION,
    timestamp: timestamp.toISOString(),
    data,
  });
}

type Attempt = {
  ok: boolean;
  statusCode: number | null;
  failure: CalloutFailure | null;
  retryAfterSeconds: number | null;
  durationMs: number;
};

function retryAfter(header: string | string[] | undefined): number | null {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.max(0, (date - Date.now()) / 1000);
}

/** One signed POST. Anything but a 2xx is a failure, including a redirect, which is not followed. */
export async function sendSigned(
  url: string,
  id: string,
  payload: string,
  secrets: string[],
  timeoutMs: number = WEBHOOK_TIMEOUT_MS,
): Promise<Attempt> {
  const started = Date.now();
  try {
    const response = await calloutRequest(url, {
      method: 'POST',
      headers: signedCalloutHeaders(id, payload, secrets),
      body: payload,
      timeoutMs,
      maxResponseBytes: MAX_RESPONSE_BYTES,
    });
    const ok = response.status >= 200 && response.status < 300;

    return {
      ok,
      statusCode: response.status,
      failure: ok ? null : 'http_status',
      retryAfterSeconds: retryAfter(response.headers['retry-after']),
      durationMs: Date.now() - started,
    };
  } catch (error) {
    return {
      ok: false,
      statusCode: null,
      failure: error instanceof CalloutError ? error.failure : 'connection_failed',
      retryAfterSeconds: null,
      durationMs: Date.now() - started,
    };
  }
}

/**
 * When the next attempt is due, or null when there is none and the delivery is dead. A
 * `Retry-After` longer than the schedule's own delay is honored, up to the schedule's longest.
 */
export function nextAttemptAt(attempts: number, at: Date, retryAfterSeconds: number | null) {
  const scheduled = WEBHOOK_RETRY_SCHEDULE_SECONDS[attempts];
  if (scheduled === undefined) return null;

  const longest = WEBHOOK_RETRY_SCHEDULE_SECONDS[WEBHOOK_RETRY_SCHEDULE_SECONDS.length - 1];
  const wait = Math.max(scheduled, Math.min(retryAfterSeconds ?? 0, longest));
  // Up to 10% later, so endpoints that failed together do not retry together.
  return addSeconds(at, wait * (1 + Math.random() * 0.1));
}

async function recordOutcome(
  delivery: WebhookDelivery,
  endpoint: WebhookEndpoint,
  attempt: Attempt,
) {
  const at = now();
  const attempts = delivery.attempts + 1;
  const next = attempt.ok ? null : nextAttemptAt(attempts, at, attempt.retryAfterSeconds);
  const status: WebhookDeliveryStatus = attempt.ok ? 'succeeded' : next ? 'failed' : 'dead';

  await delivery.update({
    status,
    attempts,
    nextAttemptAt: next,
    lastAttemptAt: at,
    lastStatusCode: attempt.statusCode,
    lastFailure: attempt.failure,
  });

  if (attempt.ok) {
    if (endpoint.failingSince) await endpoint.update({ failingSince: null });
    return;
  }

  // 410 is the receiver saying the endpoint is gone for good.
  if (attempt.statusCode === 410) {
    await disableEndpoint(endpoint, 'gone');
    return;
  }

  const failingSince = endpoint.failingSince ?? at;
  if (at.getTime() - failingSince.getTime() >= WEBHOOK_FAILING_DISABLE_SECONDS * 1000) {
    await disableEndpoint(endpoint, 'failing');
  } else if (!endpoint.failingSince) {
    await endpoint.update({ failingSince });
  }
}

async function disableEndpoint(endpoint: WebhookEndpoint, reason: 'gone' | 'failing') {
  if (!endpoint.enabled) return;
  await endpoint.update({ enabled: false, disabledReason: reason });
  logger.warn(`Webhook ${endpoint.id} disabled: ${reason}`);
  await AuthEventService.logContext({
    type: 'webhook_endpoint_disabled',
    metadata: { endpointId: endpoint.id, reason },
  });
}

export async function attemptDelivery(delivery: WebhookDelivery, endpoint: WebhookEndpoint) {
  const attempt = await sendSigned(
    endpoint.url,
    delivery.id,
    delivery.payload,
    signingSecrets(endpoint),
  );
  await recordOutcome(delivery, endpoint, attempt);
  return attempt;
}

/** Sends `webhook.test` to one endpoint now, whatever it subscribes to, and logs it as a delivery. */
export async function sendTestEvent(id: string): Promise<CalloutTestResponse> {
  const endpoint = await getEndpoint(id);
  const deliveryId = randomUUID();
  const delivery = await WebhookDelivery.create({
    id: deliveryId,
    endpointId: endpoint.id,
    eventType: WEBHOOK_TEST_EVENT_TYPE,
    payload: body(deliveryId, WEBHOOK_TEST_EVENT_TYPE, now(), { endpointId: endpoint.id }),
    status: 'pending',
    nextAttemptAt: null,
  });

  const attempt = await sendSigned(
    endpoint.url,
    delivery.id,
    delivery.payload,
    signingSecrets(endpoint),
  );
  // A test is one attempt: it is never retried and never disables the endpoint.
  await delivery.update({
    status: attempt.ok ? 'succeeded' : 'dead',
    attempts: 1,
    lastAttemptAt: now(),
    lastStatusCode: attempt.statusCode,
    lastFailure: attempt.failure,
  });

  return {
    ok: attempt.ok,
    failure: attempt.failure,
    statusCode: attempt.statusCode,
    durationMs: attempt.durationMs,
  };
}

export async function getDelivery(deliveryId: string) {
  const delivery = await WebhookDelivery.findByPk(deliveryId);
  if (!delivery) throw new WebhookError(404, 'Delivery not found');
  return delivery;
}

/**
 * One attempt now, with the same `webhook-id` and body and a fresh timestamp and signature, so a
 * receiver that already has the event can drop it.
 */
export async function redeliver(deliveryId: string) {
  const delivery = await getDelivery(deliveryId);
  const endpoint = await getEndpoint(delivery.endpointId);
  await attemptDelivery(delivery, endpoint);
  return delivery;
}

function encodeCursor(delivery: WebhookDelivery) {
  return Buffer.from(`${delivery.createdAt.toISOString()}|${delivery.id}`).toString('base64url');
}

function decodeCursor(cursor: string): { createdAt: Date; id: string } {
  const [createdAt, id] = Buffer.from(cursor, 'base64url').toString('utf8').split('|');
  const at = new Date(createdAt);
  if (!id || Number.isNaN(at.getTime())) throw new WebhookError(400, 'Invalid cursor');
  return { createdAt: at, id };
}

export async function listDeliveries(query: WebhookDeliveryQuery) {
  const conditions: WhereOptions<WebhookDeliveryAttributes>[] = [];
  if (query.endpointId) conditions.push({ endpointId: query.endpointId });
  if (query.status) conditions.push({ status: query.status });
  if (query.eventType) conditions.push({ eventType: query.eventType });
  if (query.cursor) {
    const { createdAt, id } = decodeCursor(query.cursor);
    conditions.push({
      [Op.or]: [{ createdAt: { [Op.lt]: createdAt } }, { createdAt, id: { [Op.lt]: id } }],
    });
  }

  const rows = await WebhookDelivery.findAll({
    where: conditions.length ? { [Op.and]: conditions } : {},
    order: [
      ['createdAt', 'DESC'],
      ['id', 'DESC'],
    ],
    limit: query.limit + 1,
  });

  const page = rows.slice(0, query.limit);
  return {
    deliveries: page,
    nextCursor: rows.length > query.limit ? encodeCursor(page[page.length - 1]) : null,
  };
}

type CursorRow = { lastSeq: string };
type HeadRow = { head: string };

async function subjectFor(event: DispatchableAuthEvent, transaction: Transaction) {
  if (WEBHOOK_SOURCE_TYPES[event.type] !== 'user.created' || !event.user_id) return null;
  const user = await User.findByPk(event.user_id, {
    attributes: ['email', 'phone'],
    transaction,
  });
  return user ? { email: user.email ?? null, phone: user.phone ?? null } : null;
}

/**
 * Turns committed audit rows past the cursor into deliveries (ADR 0005, D2). Rows are read by
 * `seq`, and the chain trigger holds the chain head row from insert to commit, so committed rows
 * always form a gapless prefix: a cursor never steps past a row still to commit. On first run the
 * cursor starts at the newest row, so turning webhooks on does not replay history.
 *
 * Returns how many audit rows were read, so the loop knows whether to run again at once.
 */
export async function dispatchWebhooks(): Promise<number> {
  const sequelize = getSequelize();

  return sequelize.transaction(async (transaction) => {
    const [{ locked }] = await sequelize.query<{ locked: boolean }>(
      'SELECT pg_try_advisory_xact_lock(:key) AS locked',
      { replacements: { key: DISPATCH_LOCK_KEY }, type: QueryTypes.SELECT, transaction },
    );
    if (!locked) return 0;

    const [cursor] = await sequelize.query<CursorRow>(
      'SELECT "lastSeq" FROM public.event_dispatch_cursors WHERE name = :name',
      { replacements: { name: CURSOR_NAME }, type: QueryTypes.SELECT, transaction },
    );

    if (!cursor) {
      const [{ head }] = await sequelize.query<HeadRow>(
        'SELECT coalesce(max(seq), 0) AS head FROM public.auth_events',
        { type: QueryTypes.SELECT, transaction },
      );
      await sequelize.query(
        'INSERT INTO public.event_dispatch_cursors (name, "lastSeq", "updatedAt") VALUES (:name, :head, now())',
        { replacements: { name: CURSOR_NAME, head }, transaction },
      );
      return 0;
    }

    const rows = await sequelize.query<DispatchableAuthEvent>(
      `SELECT seq, type, user_id, session_id, metadata, created_at
         FROM public.auth_events
        WHERE seq > :last
        ORDER BY seq
        LIMIT :limit`,
      {
        replacements: { last: cursor.lastSeq, limit: DISPATCH_BATCH },
        type: QueryTypes.SELECT,
        transaction,
      },
    );
    if (rows.length === 0) return 0;

    // Disabled endpoints get their deliveries too, held with no attempt due, so turning one back
    // on catches it up instead of losing what happened while it was off (ADR 0005, E4).
    const endpoints = await WebhookEndpoint.findAll({ transaction });

    for (const row of rows) {
      const subscribed = endpoints.filter((endpoint) =>
        endpoint.eventTypes.includes(WEBHOOK_SOURCE_TYPES[row.type] as WebhookEventType),
      );
      if (subscribed.length === 0) continue;

      const event = webhookEventFor(row, await subjectFor(row, transaction));
      if (!event) continue;

      for (const endpoint of subscribed) {
        const id = randomUUID();
        await sequelize.query(
          `INSERT INTO public.webhook_deliveries
             (id, "endpointId", "eventType", "authEventSeq", payload, status, attempts,
              "nextAttemptAt", "createdAt", "updatedAt")
           VALUES (:id, :endpointId, :eventType, :seq, :payload, 'pending', 0,
                   CASE WHEN :held THEN NULL ELSE now() END, now(), now())
           ON CONFLICT ("endpointId", "authEventSeq") DO NOTHING`,
          {
            replacements: {
              id,
              endpointId: endpoint.id,
              held: !endpoint.enabled,
              eventType: event.type,
              seq: row.seq,
              payload: body(id, event.type, new Date(row.created_at), event.data),
            },
            transaction,
          },
        );
      }
    }

    await sequelize.query(
      'UPDATE public.event_dispatch_cursors SET "lastSeq" = :seq, "updatedAt" = now() WHERE name = :name',
      { replacements: { seq: rows[rows.length - 1].seq, name: CURSOR_NAME }, transaction },
    );

    return rows.length;
  });
}

/**
 * Claims due deliveries and sends them. A claim pushes `nextAttemptAt` past the request timeout
 * inside a short transaction with SKIP LOCKED, so two replicas never send the same attempt and a
 * replica that dies mid-send leaves the delivery due again shortly after.
 */
export async function deliverDue(): Promise<number> {
  const sequelize = getSequelize();
  const lease = addSeconds(now(), WEBHOOK_TIMEOUT_MS / 1000 + 30);

  const claimed = await sequelize.transaction(async (transaction) => {
    const rows = await sequelize.query<{ id: string }>(
      `SELECT id FROM public.webhook_deliveries
        WHERE status IN ('pending', 'failed') AND "nextAttemptAt" <= now()
        ORDER BY "nextAttemptAt"
        LIMIT :limit
        FOR UPDATE SKIP LOCKED`,
      { replacements: { limit: DELIVERY_BATCH }, type: QueryTypes.SELECT, transaction },
    );
    if (rows.length === 0) return [];

    const ids = rows.map((row) => row.id);
    await WebhookDelivery.update(
      { nextAttemptAt: lease },
      { where: { id: { [Op.in]: ids } }, transaction },
    );
    return ids;
  });

  if (claimed.length === 0) return 0;

  const deliveries = await WebhookDelivery.findAll({ where: { id: { [Op.in]: claimed } } });
  const endpoints = new Map(
    (
      await WebhookEndpoint.findAll({
        where: { id: { [Op.in]: [...new Set(deliveries.map((d) => d.endpointId))] } },
      })
    ).map((endpoint) => [endpoint.id, endpoint]),
  );

  await Promise.all(
    deliveries.map(async (delivery) => {
      const endpoint = endpoints.get(delivery.endpointId);
      // Disabled after it was queued: hold the delivery until the endpoint is turned back on.
      if (!endpoint || !endpoint.enabled) {
        await delivery.update({ nextAttemptAt: null });
        return;
      }
      await attemptDelivery(delivery, endpoint);
    }),
  );

  return claimed.length;
}

export async function pruneDeliveries(at: Date = now()) {
  return WebhookDelivery.destroy({
    where: { createdAt: { [Op.lt]: addSeconds(at, -DELIVERY_RETENTION_DAYS * 24 * 60 * 60) } },
  });
}

const TICK_MS = 1000;
const PRUNE_EVERY_TICKS = 3600;

/** One pass of dispatch and delivery. Errors are logged, not thrown, so the loop keeps running. */
export async function runWebhookTick(tick: number) {
  try {
    while ((await dispatchWebhooks()) === DISPATCH_BATCH) {
      // A full batch means more rows are waiting.
    }
    while ((await deliverDue()) === DELIVERY_BATCH) {
      // Likewise for due deliveries.
    }
    if (tick % PRUNE_EVERY_TICKS === 0) await pruneDeliveries();
  } catch (error) {
    logger.error(`Webhook tick failed: ${(error as Error).message}`);
  }
}

/** Polls once a second. The loop is cheap when idle: two indexed reads. */
export function startWebhookDelivery() {
  let tick = 0;
  let running = false;
  const timer = setInterval(() => {
    if (running) return;
    running = true;
    void runWebhookTick(tick++).finally(() => {
      running = false;
    });
  }, TICK_MS);
  timer.unref();
  return timer;
}
