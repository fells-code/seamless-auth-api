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
import { recordBackchannelLogoutTargets } from './oidcBackchannelLogout.js';

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

// RFC 8628 section 3.5: a client polling with an expired device code is told
// `expired_token`, which the library answers only when it is handed the expired code. The
// code stays readable by id for this long after it expires, so a client polling at any
// sane interval hears why, and is then purged as usual.
export const DEVICE_CODE_EXPIRED_GRACE_MS = 1000 * 60 * 10;

function deviceCodeGraceCutoff(now: Date) {
  return new Date(now.getTime() - DEVICE_CODE_EXPIRED_GRACE_MS);
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
    return { created: await insertIfAbsent(model, id, payload, row.expiresAt, now) };
  }

  await OidcPayload.upsert(row);

  if (model === 'Session' && row.sessionId) {
    await recordBackchannelLogoutTargets(
      row.sessionId,
      payload,
      row.expiresAt,
      hasOidcGrantForSession,
    );
  }

  return { created: true };
}

/**
 * Insert only if absent, in one statement, so two requests replaying the same value cannot
 * both see "absent" and both succeed. An expired row may be taken over, since the value it
 * guarded can no longer be presented.
 */
async function insertIfAbsent(
  model: string,
  id: string,
  payload: Record<string, unknown>,
  expiresAt: Date,
  now: Date,
): Promise<boolean> {
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
      replacements: { id, model, payload: JSON.stringify(payload), expiresAt, now },
      type: QueryTypes.SELECT,
    },
  );

  return inserted.length > 0;
}

/**
 * Records an inbound OAuth state as used, true only the first time. Kept under a model the
 * edge's payload routes cannot name, so the edge can neither read nor pre-claim states.
 */
export function claimOAuthStateUse(stateHash: string, expiresAt: Date) {
  return insertIfAbsent('OAuthStateReplay', stateHash, {}, expiresAt, new Date());
}

async function findOne(
  where: WhereOptions<OidcPayloadAttributes>,
  expiresAfter = new Date(),
): Promise<OidcPayloadRecord | null> {
  const row = await OidcPayload.findOne({
    where: {
      ...where,
      expiresAt: { [Op.gt]: expiresAfter },
    } as WhereOptions<OidcPayloadAttributes>,
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

// Written only by bindOidcSession, after the API has checked the user's own access token for
// the session, and kept under a model the edge's payload routes cannot name. The edge's own
// Grant rows say whatever the edge sends, so on their own they bind nothing.
const SESSION_BINDING = 'SessionBinding';

/**
 * Records that a provider sign-in for the client happened on the session. Lasts as long as
 * the longest provider grant can, and goes with the session's other provider records when
 * the session is revoked.
 */
export async function bindOidcSession(sessionId: string, userId: string, clientId: string) {
  await OidcPayload.upsert({
    id: `${sessionId}:${clientId}`,
    model: SESSION_BINDING,
    payload: { accountId: userId, clientId },
    grantId: null,
    userCode: null,
    uid: null,
    sessionId,
    expiresAt: new Date(Date.now() + MAX_EXPIRES_IN_SECONDS * 1000),
  });
}

function findBinding(where: Record<string, unknown>) {
  return OidcPayload.findOne({
    where: {
      ...where,
      model: SESSION_BINDING,
      expiresAt: { [Op.gt]: new Date() },
    } as WhereOptions<OidcPayloadAttributes>,
  });
}

/** Whether a provider sign-in for any client was bound to the session. */
export async function isOidcSessionBound(sessionId: string) {
  if (!isUuid(sessionId)) return false;

  return Boolean(await findBinding({ sessionId }));
}

/**
 * Whether the session is bound to this client and a live provider grant for the client was
 * stored against it. The grant is still required so that revoking it ends access.
 */
export async function hasOidcGrantForSession(sessionId: string, clientId: string) {
  if (!isUuid(sessionId)) return false;

  const binding = await findBinding({ id: `${sessionId}:${clientId}` });
  if (binding?.payload.clientId !== clientId) return false;

  // One first-party session can sign in to several clients, so the client is part of the
  // query rather than checked on whichever grant comes back first.
  const grant = await OidcPayload.findOne({
    where: {
      model: 'Grant',
      sessionId,
      payload: { clientId },
      expiresAt: { [Op.gt]: new Date() },
    } as WhereOptions<OidcPayloadAttributes>,
  });

  return grant?.payload.clientId === clientId;
}

/** Whether the user signed in to the client and still holds a live provider grant for it. */
export async function hasOidcGrantForUser(userId: string, clientId: string) {
  if (!isUuid(userId)) return false;

  const binding = await findBinding({ payload: { accountId: userId, clientId } });
  if (binding?.payload.accountId !== userId || binding.payload.clientId !== clientId) {
    return false;
  }

  const grant = await OidcPayload.findOne({
    where: {
      model: 'Grant',
      payload: { accountId: userId, clientId },
      expiresAt: { [Op.gt]: new Date() },
    } as WhereOptions<OidcPayloadAttributes>,
  });

  return grant?.payload.accountId === userId && grant.payload.clientId === clientId;
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
  const now = new Date();
  return findOne({ model, id }, model === 'DeviceCode' ? deviceCodeGraceCutoff(now) : now);
}

export function findOidcPayloadByUserCode(model: OidcPayloadModel, userCode: string) {
  return findOne({ model, userCode });
}

export function findOidcPayloadByUid(model: OidcPayloadModel, uid: string) {
  return findOne({ model, uid });
}

/**
 * True only for the caller whose update set `consumedAt`. The condition is in the one
 * statement, so of two refreshes racing with the same token exactly one wins, and the edge
 * treats the other as reuse rather than issuing a second rotation.
 */
export async function consumeOidcPayload(model: OidcPayloadModel, id: string) {
  const [affected] = await OidcPayload.update(
    { consumedAt: new Date() },
    {
      where: {
        model,
        id,
        consumedAt: { [Op.is]: null },
        expiresAt: { [Op.gt]: new Date() },
      } as WhereOptions<OidcPayloadAttributes>,
    },
  );
  return affected > 0;
}

export async function destroyOidcPayload(model: OidcPayloadModel, id: string) {
  await OidcPayload.destroy({ where: { model, id } });
}

export async function revokeOidcPayloadsByGrant(model: OidcPayloadModel, grantId: string) {
  await OidcPayload.destroy({ where: { model, grantId } });
}

export async function purgeExpiredOidcPayloads(now = new Date()) {
  return OidcPayload.destroy({
    where: {
      [Op.or]: [
        { model: { [Op.ne]: 'DeviceCode' }, expiresAt: { [Op.lte]: now } },
        { expiresAt: { [Op.lte]: deviceCodeGraceCutoff(now) } },
      ],
    } as WhereOptions<OidcPayloadAttributes>,
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
