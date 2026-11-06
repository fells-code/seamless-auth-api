/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  seamlessBuiltInResource,
  SESSION_EXCHANGE_ISSUED_TOKEN_TYPE,
  SESSION_EXCHANGE_SCOPE,
  type SessionExchangeResponse,
} from '@seamless-auth/types';
import { Request } from 'express';
import { createLocalJWKSet, type JSONWebKeySet, type JWTPayload, jwtVerify } from 'jose';
import { Op, WhereOptions } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { createRefreshTokenLookup, generateRefreshToken } from '../lib/token.js';
import { OidcPayload, OidcPayloadAttributes } from '../models/oidcPayloads.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { computeSessionTimes, parseDurationToSeconds } from '../utils/utils.js';
import { mintAccessToken } from './accessTokenService.js';
import { AuthEventService } from './authEventService.js';
import { resolveCurrentSession } from './oidcAuthContext.js';
import { findActiveOidcClient, isSessionExchangeClient } from './oidcClientRegistry.js';
import { SESSION_EXCHANGE_TOKEN, SessionExchangeTokenPayload } from './oidcPayloadStore.js';
import { getOidcPublicJwks } from './oidcProviderKeys.js';
import { revokeSessionChain } from './sessionService.js';

const logger = getLogger('sessionExchange');

const AUTHORIZATION_CODE_GRANT = 'authorization_code';
const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export type SessionExchangeOutcome =
  { ok: true; response: SessionExchangeResponse } | { ok: false; replayed: boolean };

const REFUSED: SessionExchangeOutcome = { ok: false, replayed: false };

type SubjectClaims = JWTPayload & { sub: string; jti: string; client_id: string };

function refuse(reason: string): SessionExchangeOutcome {
  logger.warn(`Session exchange refused: ${reason}`);
  return REFUSED;
}

/** ADR 0003, X4 to X7: only a token the API signed for this one purpose gets past here. */
async function verifySubjectToken(token: string): Promise<SubjectClaims | null> {
  const { oidc_issuer } = await getSystemConfig();
  if (!oidc_issuer) return null;

  const audience = seamlessBuiltInResource(oidc_issuer);

  let claims: JWTPayload;
  try {
    const jwks = createLocalJWKSet({ keys: getOidcPublicJwks().keys } as JSONWebKeySet);
    ({ payload: claims } = await jwtVerify(token, jwks, {
      issuer: oidc_issuer,
      audience,
      algorithms: ['RS256'],
      typ: 'at+jwt',
      requiredClaims: ['exp', 'iat', 'sub', 'jti', 'client_id', 'scope'],
    }));
  } catch (error) {
    logger.debug(`Subject token refused: ${(error as Error).message}`);
    return null;
  }

  const clientId: unknown = claims.client_id;
  if (
    claims.aud !== audience ||
    claims.scope !== SESSION_EXCHANGE_SCOPE ||
    typeof clientId !== 'string' ||
    claims.sub === clientId
  ) {
    return null;
  }

  return claims as SubjectClaims;
}

function findRecord(jti: string) {
  return OidcPayload.findOne({ where: { model: SESSION_EXCHANGE_TOKEN, id: jti } });
}

/** Whatever the first presentation created goes, wherever its refresh chain has reached. */
async function handleReplay(
  claims: SubjectClaims,
  record: OidcPayload,
  req: Request,
): Promise<SessionExchangeOutcome> {
  const { childSessionId } = record.payload as SessionExchangeTokenPayload;
  const child = childSessionId ? await Session.findByPk(childSessionId) : null;

  if (child) {
    await revokeSessionChain(child, 'session_exchange_replayed');
  }

  await AuthEventService.log({
    userId: claims.sub,
    sessionId: child?.id ?? null,
    type: 'session_exchange_replayed',
    req,
    metadata: {
      clientId: claims.client_id,
      parentSessionId: child?.parentSessionId ?? record.sessionId,
    },
  });

  return { ok: false, replayed: true };
}

function issuedChildTimes(parent: Session, ttls: { absoluteTtl: string; idleTtl: string }) {
  const { expiresAt, idleExpiresAt } = computeSessionTimes(ttls);
  const cap = Math.min(expiresAt.getTime(), new Date(parent.expiresAt).getTime());

  return {
    expiresAt: new Date(cap),
    idleExpiresAt: new Date(Math.min(idleExpiresAt.getTime(), cap)),
  };
}

/**
 * ADR 0003, X5. The passkey behind a device grant proved who approved, not who holds the
 * token, so that child starts with nothing (ADR 0001, D10).
 */
function inheritedAssurance(parent: Session, grantType: string) {
  if (grantType === DEVICE_CODE_GRANT) {
    return { authMethods: [], authTime: null, stepUpVerifiedAt: null, stepUpMethod: null };
  }

  return {
    authMethods: parent.authMethods ?? [],
    authTime: parent.authTime ?? parent.chainStartedAt ?? parent.createdAt ?? null,
    stepUpVerifiedAt: parent.stepUpVerifiedAt ?? null,
    stepUpMethod: parent.stepUpMethod ?? null,
  };
}

/**
 * Consumes the record and creates the child in one transaction. Concurrent presentations
 * queue on the record's row, so the losers read a `childSessionId` the winner has committed
 * and can revoke it, rather than finding the record consumed with nothing to revoke yet.
 */
async function consumeAndIssue(
  record: OidcPayload,
  parent: Session,
  user: User,
  clientId: string,
  grantType: string,
  req: Request,
) {
  const { access_token_ttl, refresh_token_ttl, session_idle_ttl } = await getSystemConfig();
  const now = new Date();
  const { expiresAt, idleExpiresAt } = issuedChildTimes(parent, {
    absoluteTtl: refresh_token_ttl || '1d',
    idleTtl: session_idle_ttl || '8h',
  });
  const refreshToken = generateRefreshToken();

  const issued = await OidcPayload.sequelize!.transaction(async (transaction) => {
    const [consumed] = await OidcPayload.update(
      { consumedAt: now },
      {
        where: {
          model: SESSION_EXCHANGE_TOKEN,
          id: record.id,
          consumedAt: { [Op.is]: null },
          expiresAt: { [Op.gt]: now },
        } as WhereOptions<OidcPayloadAttributes>,
        transaction,
      },
    );
    if (consumed === 0) return null;

    const child = await Session.create(
      {
        userId: user.id,
        infraId: parent.infraId,
        organizationId: parent.organizationId,
        mode: 'server',
        refreshTokenLookup: createRefreshTokenLookup(refreshToken),
        userAgent: req.get('user-agent'),
        ipAddress: req.ip,
        expiresAt,
        idleExpiresAt,
        chainStartedAt: now,
        lastUsedAt: now,
        parentSessionId: parent.id,
        exchangeClientId: clientId,
        exchangeGrantType: grantType,
        ...inheritedAssurance(parent, grantType),
      },
      { transaction },
    );

    await OidcPayload.update(
      { payload: { ...record.payload, childSessionId: child.id } },
      {
        where: {
          model: SESSION_EXCHANGE_TOKEN,
          id: record.id,
        } as WhereOptions<OidcPayloadAttributes>,
        transaction,
      },
    );

    // Inside, so a signing failure hands the token back rather than spending it.
    const minted = await mintAccessToken({
      session: { id: child.id, organizationId: parent.organizationId, recovery: false },
      user,
      transaction,
    });

    return { child, ...minted };
  });

  if (!issued) return null;

  return {
    ...issued,
    response: {
      message: 'Success',
      token: issued.token,
      refreshToken,
      sub: user.id,
      sessionId: issued.child.id,
      organizationId: issued.organizationId,
      roles: user.roles,
      email: user.email,
      phone: user.phone,
      ttl: parseDurationToSeconds(access_token_ttl || '15m'),
      refreshTtl: Math.floor((expiresAt.getTime() - now.getTime()) / 1000),
      issued_token_type: SESSION_EXCHANGE_ISSUED_TOKEN_TYPE,
    } as SessionExchangeResponse,
  };
}

/**
 * `POST /sessions/exchange` (ADR 0003). The one place a provider token is accepted, and only
 * to mint a first-party session (ADR 0001, D11). Every token failure answers the same, so
 * the route cannot be used to learn about sessions; the reason goes to the log.
 */
export async function exchangeSubjectToken(
  subjectToken: string,
  req: Request,
): Promise<SessionExchangeOutcome> {
  const claims = await verifySubjectToken(subjectToken);
  if (!claims) return refuse('token did not verify');

  const record = await findRecord(claims.jti);
  if (!record) return refuse('no signing record');

  const payload = record.payload as SessionExchangeTokenPayload;
  if (payload.accountId !== claims.sub || payload.clientId !== claims.client_id) {
    return refuse('signing record names another user or client');
  }

  if (record.consumedAt) return handleReplay(claims, record, req);

  if (record.expiresAt <= new Date()) return refuse('signing record expired');

  const { grantType } = payload;
  if (grantType !== AUTHORIZATION_CODE_GRANT && grantType !== DEVICE_CODE_GRANT) {
    return refuse('signing record names a grant that cannot exchange');
  }

  const client = await findActiveOidcClient(claims.client_id);
  if (!client || !isSessionExchangeClient(client)) return refuse('client cannot exchange');

  const parent = record.sessionId ? await resolveCurrentSession(record.sessionId) : null;
  if (!parent || parent.userId !== claims.sub) return refuse('parent session is not live');
  if (parent.recovery) return refuse('parent is a recovery session');
  if (parent.parentSessionId) return refuse('parent is an exchanged session');

  const user = await User.findOne({ where: { id: parent.userId, revoked: false } });
  if (!user) return refuse('user is not active');

  const issued = await consumeAndIssue(record, parent, user, client.id, grantType, req);

  if (!issued) {
    const latest = await findRecord(claims.jti);
    return latest?.consumedAt
      ? handleReplay(claims, latest, req)
      : refuse('signing record expired');
  }

  // An admin turning the client off revokes its sessions after writing the flag, so reading
  // the flag after the child is committed means one of the two always sees the other.
  const current = await findActiveOidcClient(client.id);
  if (!current || !isSessionExchangeClient(current)) {
    await revokeSessionChain(issued.child, 'session_exchange_disabled');
    return refuse('client stopped being able to exchange');
  }

  await AuthEventService.log({
    userId: user.id,
    sessionId: issued.child.id,
    type: 'session_exchanged',
    req,
    metadata: { clientId: client.id, grantType, parentSessionId: parent.id },
  });

  return { ok: true, response: issued.response };
}
