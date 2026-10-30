/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type {
  OidcPayloadModel,
  OidcPayloadRecord,
  OidcPayloadUpsertRequest,
} from '@seamless-auth/types';
import { Op, QueryTypes, WhereOptions } from 'sequelize';

import { OidcPayload, OidcPayloadAttributes } from '../models/oidcPayloads.js';
import getLogger from '../utils/logger.js';
import { isUuid, resolveCurrentSession } from './oidcAuthContext.js';

const logger = getLogger('oidcPayloadStore');

export class InvalidSessionIdError extends Error {
  constructor() {
    super('sessionId is not a session id');
    this.name = 'InvalidSessionIdError';
  }
}

// Longer than any provider session or refresh lifetime the admin routes allow, so a record
// asking for more is not one the library produced, and the purge would never reach it.
export const MAX_EXPIRES_IN_SECONDS = 60 * 60 * 24 * 90;

export class ExpiryTooLongError extends Error {
  constructor() {
    super(`expiresIn may be at most ${MAX_EXPIRES_IN_SECONDS} seconds`);
    this.name = 'ExpiryTooLongError';
  }
}

function stringField(payload: Record<string, unknown>, key: string) {
  const value = payload[key];
  return typeof value === 'string' && value ? value : null;
}

export async function upsertOidcPayload(
  model: OidcPayloadModel,
  id: string,
  { payload, expiresIn, sessionId }: OidcPayloadUpsertRequest,
): Promise<{ created: boolean }> {
  if (sessionId !== undefined && !isUuid(sessionId)) {
    throw new InvalidSessionIdError();
  }

  if (expiresIn > MAX_EXPIRES_IN_SECONDS) {
    throw new ExpiryTooLongError();
  }

  const now = new Date();
  const row = {
    id,
    model,
    payload,
    grantId: stringField(payload, 'grantId'),
    userCode: stringField(payload, 'userCode'),
    uid: stringField(payload, 'uid'),
    sessionId: sessionId ?? null,
    expiresAt: new Date(now.getTime() + expiresIn * 1000),
  };

  if (model === 'ReplayDetection') {
    return insertReplayDetection(row, now);
  }

  await OidcPayload.upsert(row);
  return { created: true };
}

/**
 * Insert only if absent, in one statement, so two requests replaying the same assertion
 * cannot both see "absent" and both succeed. An expired row may be taken over, since the
 * value it guarded can no longer be presented.
 */
async function insertReplayDetection(
  row: Omit<OidcPayloadAttributes, 'consumedAt' | 'createdAt' | 'updatedAt'>,
  now: Date,
): Promise<{ created: boolean }> {
  const inserted = await OidcPayload.sequelize!.query<{ id: string }>(
    `INSERT INTO public.oidc_payloads
       (id, model, payload, "expiresAt", "createdAt", "updatedAt")
     VALUES (:id, :model, CAST(:payload AS jsonb), :expiresAt, :now, :now)
     ON CONFLICT (model, id) DO UPDATE
       SET payload = EXCLUDED.payload, "expiresAt" = EXCLUDED."expiresAt",
           "consumedAt" = NULL, "updatedAt" = EXCLUDED."updatedAt"
       WHERE oidc_payloads."expiresAt" <= :now
     RETURNING id`,
    {
      replacements: {
        id: row.id,
        model: row.model,
        payload: JSON.stringify(row.payload),
        expiresAt: row.expiresAt,
        now,
      },
      type: QueryTypes.SELECT,
    },
  );

  return { created: inserted.length > 0 };
}

async function findOne(
  where: WhereOptions<OidcPayloadAttributes>,
): Promise<OidcPayloadRecord | null> {
  const row = await OidcPayload.findOne({
    where: { ...where, expiresAt: { [Op.gt]: new Date() } } as WhereOptions<OidcPayloadAttributes>,
  });

  if (!row) return null;

  // Revoking a session in any of the usual ways ends provider access at once, without each
  // of those paths having to know the provider exists.
  if (row.sessionId && !(await resolveCurrentSession(row.sessionId))) {
    logger.info(`Hiding ${row.model} ${row.id}: its session is no longer live`);
    return null;
  }

  return {
    payload: row.payload,
    sessionId: row.sessionId,
    expiresAt: row.expiresAt.toISOString(),
    consumedAt: row.consumedAt ? row.consumedAt.toISOString() : null,
  };
}

/** Whether a live provider grant for this client was stored against the session. */
export async function hasOidcGrantForSession(sessionId: string, clientId: string) {
  if (!isUuid(sessionId)) return false;

  const grant = await OidcPayload.findOne({
    where: {
      model: 'Grant',
      sessionId,
      expiresAt: { [Op.gt]: new Date() },
    } as WhereOptions<OidcPayloadAttributes>,
  });

  return grant?.payload.clientId === clientId;
}

/**
 * The current row of a session that holds a provider grant for the client, or null. What
 * every user-facing lookup and signature is bound to, so the edge can reach only the users
 * signing in through it, and only for the client asking.
 */
export async function findGrantBoundSession(sessionId: string, clientId: string) {
  const session = await resolveCurrentSession(sessionId);

  if (!session || !(await hasOidcGrantForSession(sessionId, clientId))) return null;

  return session;
}

export function findOidcPayload(model: OidcPayloadModel, id: string) {
  return findOne({ model, id });
}

export function findOidcPayloadByUserCode(model: OidcPayloadModel, userCode: string) {
  return findOne({ model, userCode });
}

export function findOidcPayloadByUid(model: OidcPayloadModel, uid: string) {
  return findOne({ model, uid });
}

export async function consumeOidcPayload(model: OidcPayloadModel, id: string) {
  await OidcPayload.update(
    { consumedAt: new Date() },
    { where: { model, id, consumedAt: { [Op.is]: null } } as WhereOptions<OidcPayloadAttributes> },
  );
}

export async function destroyOidcPayload(model: OidcPayloadModel, id: string) {
  await OidcPayload.destroy({ where: { model, id } });
}

export async function revokeOidcPayloadsByGrant(model: OidcPayloadModel, grantId: string) {
  await OidcPayload.destroy({ where: { model, grantId } });
}

export async function purgeExpiredOidcPayloads(now = new Date()) {
  return OidcPayload.destroy({
    where: { expiresAt: { [Op.lte]: now } } as WhereOptions<OidcPayloadAttributes>,
  });
}

const PURGE_INTERVAL_MS = 1000 * 60 * 60;

export function startOidcPayloadPurge() {
  setInterval(() => {
    purgeExpiredOidcPayloads()
      .then((count) => {
        if (count > 0) logger.info(`Purged ${count} expired provider records`);
      })
      .catch((error) => logger.error(`Provider record purge failed: ${error}`));
  }, PURGE_INTERVAL_MS).unref();
}
