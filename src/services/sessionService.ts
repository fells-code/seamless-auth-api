/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { importSPKI, jwtVerify } from 'jose';
import jwt from 'jsonwebtoken';

import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { getSecret } from '../utils/secretsStore.js';
import { getPublicKeyByKid } from '../utils/signingKeyStore.js';

const logger = getLogger('sessionService');

export type CookieType = 'ephemeral' | 'access';

let cachedSecret: string | null = null;

async function getInternalSecret() {
  if (cachedSecret) return cachedSecret;
  cachedSecret = await getSecret('API_SERVICE_TOKEN');
  return cachedSecret;
}

export interface ValidateSessionInput {
  type: 'cookie' | 'bearer';
  value: string;
  cookieType?: CookieType;
}

const ISSUER = process.env.ISSUER!;

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

export async function validateAccessToken(token: string) {
  const payload = await verifyJwtWithKid(token, 'access');
  if (!payload) return null;

  const { sub: userId, sid: sessionId } = payload;

  if (!userId || !sessionId) return null;

  return {
    userId,
    sessionId,
    roles: payload.roles || [],
  };
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

export async function validateBearerToken(token: string) {
  const serviceSecret = await getInternalSecret();
  let payload;

  try {
    payload = jwt.verify(token, serviceSecret, {
      issuer: process.env.APP_ORIGIN,
      audience: process.env.ISSUER,
    });
  } catch (err: Error | unknown) {
    if (err instanceof Error && err.name === 'TokenExpiredError') {
      logger.info(`Expired bearer token`);
    } else {
      logger.error(`Bearer token verification error: ${err}`);
    }
    return null;
  }

  const user = await User.findOne({
    where: { id: payload.sub as string, revoked: false },
  });

  return user ?? null;
}
