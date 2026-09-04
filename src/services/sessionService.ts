/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { importSPKI, jwtVerify } from 'jose';
import { Op } from 'sequelize';

import { createRefreshTokenLookup } from '../lib/token.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { getPublicKeyByKid } from '../utils/signingKeyStore.js';
import { decoyPrincipalAsUser, decoyPrincipalForSubject } from './decoyPrincipal.js';

const logger = getLogger('sessionService');

export type AuthTokenType = 'ephemeral' | 'access';

const ISSUER = process.env.ISSUER!;

export interface ValidatedAccessToken {
  userId: string;
  sessionId: string;
  roles: string[];
  organizationId: string | null;
}

export async function verifyJwtWithKid(token: string, expectedType?: 'access' | 'ephemeral') {
  try {
    const { payload } = await jwtVerify(
      token,
      async (header) => {
        const { kid } = header;
        if (!kid) throw new Error(`Missing kid in JWT header`);

        const publicKeyPem = await getPublicKeyByKid(kid);
        if (!publicKeyPem) throw new Error(`No public key for kid ${kid}`);

        return importSPKI(publicKeyPem, 'RS256');
      },
      {
        issuer: ISSUER,
        algorithms: ['RS256'],
      },
    );

    if (expectedType && payload.typ !== expectedType) {
      logger.warn(`JWT typ mismatch: expected '${expectedType}', got '${payload.typ}'`);
      return null;
    }

    if (payload.typ === 'access') {
      if (!payload.sub) {
        logger.warn('Access token missing sub');
        return null;
      }
      if (!payload.sid) {
        logger.warn('Access token missing sid');
        return null;
      }
    }

    if (payload.typ === 'ephemeral') {
      if (!payload.sub) {
        logger.warn('Ephemeral JWT missing sub');
        return null;
      }
    }

    return payload;
  } catch (err) {
    logger.warn('JWT verification failed:', err);
    return null;
  }
}

export async function revokeSessionChain(session: Session, reason = 'refresh_token_reuse') {
  const now = new Date();
  const seen = new Set<string>();
  let current: Session | null = session;

  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    current.revokedAt = now;
    current.revokedReason = reason;
    await current.save();

    if (!current.replacedBySessionId) break;
    current = await Session.findByPk(current.replacedBySessionId);
  }
}

export async function hardRevokeSession(session: Session, reason = 'manual_revoke') {
  session.revokedAt = new Date();
  session.revokedReason = reason;
  await session.save();
}

export async function validateAccessToken(token: string): Promise<ValidatedAccessToken | null> {
  const payload = await verifyJwtWithKid(token, 'access');
  if (!payload) return null;

  const { sub: userId, sid: sessionId } = payload;

  if (typeof userId !== 'string' || typeof sessionId !== 'string') return null;

  return {
    userId,
    sessionId,
    roles: Array.isArray(payload.roles)
      ? payload.roles.filter((role): role is string => typeof role === 'string')
      : [],
    organizationId: typeof payload.org_id === 'string' ? payload.org_id : null,
  };
}

export async function findRefreshSessionByToken(
  refreshToken: string,
  now = new Date(),
): Promise<Session | null> {
  const refreshTokenLookup = createRefreshTokenLookup(refreshToken);

  return Session.findOne({
    where: {
      revokedAt: null,
      expiresAt: { [Op.gt]: now },
      idleExpiresAt: { [Op.gt]: now },
      refreshTokenLookup,
    },
  });
}

export async function validateSessionRecord(sessionId: string) {
  const session = await Session.findByPk(sessionId);
  if (!session) return null;

  const now = new Date();

  if (session.revokedAt) return null;

  if (session.replacedBySessionId) {
    await revokeSessionChain(session);
    return null;
  }

  if (session.expiresAt < now) return null;
  if (session.idleExpiresAt < now) return null;

  return session;
}

export async function getUserFromSession(session: Session) {
  const user = await User.findOne({
    where: { id: session.userId, revoked: false },
  });

  return user ?? null;
}

export interface ValidatedBearerToken {
  user: User;
  sessionId?: string;
  organizationId?: string | null;
  decoy?: boolean;
}

export async function validateEphemeralToken(token: string): Promise<ValidatedBearerToken | null> {
  const payload = await verifyJwtWithKid(token, 'ephemeral');

  if (!payload || typeof payload.sub !== 'string') {
    return null;
  }

  const user = await User.findOne({
    where: { id: payload.sub, revoked: false },
  });

  if (user) {
    return { user };
  }

  // The signature, issuer, audience, type and expiry have all already been checked, so
  // this token was minted here. A subject that resolves to no row is therefore the
  // decoy `/login` issued for an identifier with no usable account, and the request
  // continues as that fiction rather than being rejected. Rejecting here is what used
  // to move the oracle one request later.
  //
  // A token whose user was deleted or revoked mid-flow lands here too, and is likewise
  // answered as a decoy rather than with a distinguishable 401.
  return { user: decoyPrincipalAsUser(decoyPrincipalForSubject(payload.sub)), decoy: true };
}

export async function validateBearerToken(
  token: string,
  expectedType: AuthTokenType = 'access',
): Promise<ValidatedBearerToken | null> {
  if (expectedType === 'ephemeral') {
    return validateEphemeralToken(token);
  }

  const accessToken = await validateAccessToken(token);

  if (!accessToken) {
    return null;
  }

  const session = await validateSessionRecord(accessToken.sessionId);

  if (!session) {
    return null;
  }

  if (session.userId !== accessToken.userId) {
    logger.warn('Access token subject did not match the session owner');
    return null;
  }

  const user = await getUserFromSession(session);

  return user
    ? {
        user,
        sessionId: accessToken.sessionId,
        organizationId: accessToken.organizationId,
      }
    : null;
}
