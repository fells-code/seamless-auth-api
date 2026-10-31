/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { constants, randomUUID, sign } from 'crypto';
import { Op, QueryTypes, WhereOptions } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { providerFetch } from '../lib/oauthProviderPolicy.js';
import { OidcPayload, OidcPayloadAttributes } from '../models/oidcPayloads.js';
import { Session } from '../models/sessions.js';
import getLogger from '../utils/logger.js';
import { AuthEventService } from './authEventService.js';
import { isUuid, resolveCurrentSession } from './oidcAuthContext.js';
import { findActiveOidcClient } from './oidcClientRegistry.js';
import { getActiveOidcSigningKey, getOidcPublicJwks } from './oidcProviderKeys.js';

const logger = getLogger('oidcBackchannelLogout');

/**
 * Kept under a model the edge's payload routes cannot name, so the edge can neither read
 * nor delete the record of who to tell. The library deletes the provider Session and its
 * grants during RP-initiated logout, before the first-party session is revoked, so these
 * rows are what is left to send from.
 */
export const BACKCHANNEL_LOGOUT_MODEL = 'BackchannelLogout';

const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const LOGOUT_TOKEN_TTL_SECONDS = 120;
const DELIVERY_TIMEOUT_MS = 5000;
// An RP sees a new sid each time the provider session is replaced, and may still hold an
// older one. Bounded so a long-lived session cannot grow its row without limit.
const MAX_SIDS_PER_CLIENT = 10;
const MAX_CLIENTS_PER_SESSION = 50;
const SWEEP_BATCH = 500;
const SWEEP_INTERVAL_MS = 30_000;

interface Target {
  clientId: string;
  sids: string[];
}

function targetOf(payload: Record<string, unknown>): Target | null {
  const { clientId, sids } = payload;
  if (typeof clientId !== 'string' || !Array.isArray(sids)) return null;
  return { clientId, sids: sids.filter((sid): sid is string => typeof sid === 'string') };
}

function sidsByClient(sessionPayload: Record<string, unknown>) {
  const authorizations = sessionPayload.authorizations;
  const found = new Map<string, string>();
  if (!authorizations || typeof authorizations !== 'object') return found;

  for (const [clientId, value] of Object.entries(authorizations)) {
    const sid = (value as { sid?: unknown } | null)?.sid;
    if (typeof sid === 'string' && sid && found.size < MAX_CLIENTS_PER_SESSION) {
      found.set(clientId, sid);
    }
  }
  return found;
}

/**
 * Records the `sid` each client was given in a provider Session the edge stored, so the
 * client can be told when the first-party session behind it ends. Only clients the
 * session holds a grant for are recorded: the edge cannot point logout tokens at apps the
 * user never signed in to.
 */
export async function recordBackchannelLogoutTargets(
  sessionId: string,
  sessionPayload: Record<string, unknown>,
  expiresAt: Date,
  hasGrant: (sessionId: string, clientId: string) => Promise<boolean>,
) {
  const sids = sidsByClient(sessionPayload);
  if (sids.size === 0) return;

  const existing = await OidcPayload.findAll({
    where: { model: BACKCHANNEL_LOGOUT_MODEL, sessionId } as WhereOptions<OidcPayloadAttributes>,
  });
  const known = new Map(
    existing.map((row) => [row.id, { target: targetOf(row.payload), expiresAt: row.expiresAt }]),
  );

  for (const [clientId, sid] of sids) {
    const id = `${sessionId}:${clientId}`;
    const previous = known.get(id);
    if (previous?.target?.sids.includes(sid)) continue;
    if (!(await hasGrant(sessionId, clientId))) continue;

    const merged = [...(previous?.target?.sids ?? []), sid].slice(-MAX_SIDS_PER_CLIENT);
    const later =
      previous && previous.expiresAt.getTime() > expiresAt.getTime()
        ? previous.expiresAt
        : expiresAt;

    await OidcPayload.upsert({
      id,
      model: BACKCHANNEL_LOGOUT_MODEL,
      payload: { clientId, sids: merged },
      sessionId,
      expiresAt: later,
    });
  }
}

/**
 * Takes the rows in one statement, so of two instances (or the sweep and a revocation)
 * reaching the same session, only one sends.
 */
async function claimTargets(sessionIds: string[]) {
  if (sessionIds.length === 0) return [];

  return OidcPayload.sequelize!.query<{ payload: Record<string, unknown>; sessionId: string }>(
    `DELETE FROM public.oidc_payloads
     WHERE model = :model AND "sessionId" IN (:sessionIds)
     RETURNING payload, "sessionId"`,
    {
      replacements: { model: BACKCHANNEL_LOGOUT_MODEL, sessionIds },
      type: QueryTypes.SELECT,
    },
  );
}

/** An OpenID Back-Channel Logout 1.0 logout token, signed with the active provider key. */
export function signLogoutToken(issuer: string, clientId: string, sub: string, sid: string) {
  const { activeKid } = getOidcPublicJwks();
  const key = getActiveOidcSigningKey(activeKid);
  if (!key) throw new Error('No active provider signing key');

  const iat = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', kid: activeKid, typ: 'logout+jwt' };
  const claims = {
    iss: issuer,
    aud: clientId,
    iat,
    exp: iat + LOGOUT_TOKEN_TTL_SECONDS,
    jti: randomUUID(),
    sub,
    sid,
    events: { [LOGOUT_EVENT]: {} },
  };
  const signingInput = [header, claims]
    .map((part) => Buffer.from(JSON.stringify(part)).toString('base64url'))
    .join('.');
  const signature = sign('sha256', Buffer.from(signingInput), {
    key,
    padding: constants.RSA_PKCS1_PADDING,
  }).toString('base64url');

  return `${signingInput}.${signature}`;
}

// The same destination rules as inbound OAuth providers: https, and in production no
// non-public address unless the operator allows the host.
async function post(uri: string, logoutToken: string) {
  const response = await providerFetch(uri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ logout_token: logoutToken }),
    signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
  });
  await response.body?.cancel();
  return response.status;
}

async function deliver(issuer: string, sessionId: string, userId: string, target: Target) {
  const client = await findActiveOidcClient(target.clientId);
  if (!client?.backchannelLogoutUri) return;

  for (const sid of target.sids) {
    let outcome: { status?: number; error?: string };
    try {
      const token = signLogoutToken(issuer, client.id, userId, sid);
      outcome = { status: await post(client.backchannelLogoutUri, token) };
    } catch (error) {
      outcome = { error: (error as Error).name };
    }

    const metadata = { clientId: client.id, ...outcome };
    if (outcome.status === 200 || outcome.status === 204) {
      await AuthEventService.logContext({
        userId,
        sessionId,
        type: 'oidc_backchannel_logout_sent',
        metadata,
      });
    } else {
      logger.warn(`Back-channel logout to ${client.id} failed: ${outcome.status ?? outcome.error}`);
      await AuthEventService.logContext({
        userId,
        sessionId,
        type: 'oidc_backchannel_logout_failed',
        metadata,
      });
    }
  }
}

/**
 * Tells every client recorded against these first-party sessions that the user's session
 * at the provider ended. Each client is told once: the rows are deleted as they are taken.
 */
export async function sendBackchannelLogout(sessionIds: string[]) {
  const ids = sessionIds.filter(isUuid);
  const claimed = await claimTargets(ids);
  if (claimed.length === 0) return 0;

  const { oidc_issuer } = await getSystemConfig();
  if (!oidc_issuer) return 0;

  const owners = new Map(
    (await Session.findAll({ where: { id: { [Op.in]: ids } } })).map((row) => [row.id, row.userId]),
  );

  await Promise.all(
    claimed.map(async (row) => {
      const target = targetOf(row.payload);
      const userId = owners.get(row.sessionId);
      if (!target || !userId) return;
      await deliver(oidc_issuer, row.sessionId, userId, target);
    }),
  );

  return claimed.length;
}

/**
 * Finds recorded sessions that are no longer live and sends for them. Sessions end in many
 * ways (admin revoke, sign-out everywhere, eviction, chain revocation, the user's cutoff),
 * and this catches all of them without each path having to know the provider exists.
 */
let sweepCursor = '';

export function __resetBackchannelLogoutSweep() {
  sweepCursor = '';
}

export async function sweepBackchannelLogout() {
  const rows = await OidcPayload.findAll({
    attributes: ['id', 'sessionId'],
    where: {
      model: BACKCHANNEL_LOGOUT_MODEL,
      id: { [Op.gt]: sweepCursor },
      expiresAt: { [Op.gt]: new Date() },
    } as WhereOptions<OidcPayloadAttributes>,
    order: [['id', 'ASC']],
    limit: SWEEP_BATCH,
  });

  // Walks the table a batch per run, so live sessions at the front never hide ended ones
  // further along.
  sweepCursor = rows.length === SWEEP_BATCH ? rows[rows.length - 1].id : '';

  const sessionIds = [...new Set(rows.map((row) => row.sessionId).filter(Boolean))] as string[];
  const ended: string[] = [];
  for (const sessionId of sessionIds) {
    if (!(await resolveCurrentSession(sessionId))) ended.push(sessionId);
  }

  return sendBackchannelLogout(ended);
}

export function sweepBackchannelLogoutInBackground() {
  sweepBackchannelLogout().catch((error) =>
    logger.error(`Back-channel logout sweep failed: ${error}`),
  );
}

export function startBackchannelLogoutSweep() {
  setInterval(sweepBackchannelLogoutInBackground, SWEEP_INTERVAL_MS).unref();
}
