/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { importSPKI, jwtVerify } from 'jose';
import jwt, { JwtPayload } from 'jsonwebtoken';

import { Session } from '../models/sessions';
import { User } from '../models/users';
import getLogger from '../utils/logger';
import { getSecret } from '../utils/secretsStore';
import { getPublicKeyByKid } from '../utils/signingKeyStore';

const logger = getLogger('sessionService');

export type CookieType = 'ephemeral' | 'access';

export interface ValidateSessionInput {
  type: 'cookie' | 'bearer';
  value: string;
  cookieType?: CookieType;
}

const ISSUER = process.env.ISSUER!;

async function verifyJwtWithKid(token: string, expectedType?: 'access' | 'ephemeral') {
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

export async function validateSession({
  type,
  value,
  cookieType = 'access',
}: {
  type: 'cookie' | 'bearer';
  value: string;
  cookieType?: 'access' | 'ephemeral';
}): Promise<User | null> {
  try {
    let payload: JwtPayload | string | null = null;

    if (type === 'cookie') {
      payload = await verifyJwtWithKid(value, cookieType);
      if (!payload) return null;

      if (cookieType === 'ephemeral') {
        const user = await User.findOne({
          where: { id: payload.sub, revoked: false },
        });
        return user ?? null;
      }

      if (cookieType === 'access') {
        const { sub: userId, sid: sessionId, typ } = payload;

        if (!userId || !sessionId || typ !== 'access') {
          logger.warn('Access token missing required claims');
          return null;
        }

        const session = await Session.findByPk(sessionId);
        if (!session) {
          logger.warn(`No session found for sid=${sessionId}`);
          return null;
        }

        const now = new Date();

        if (session.revokedAt) {
          logger.warn(`Session ${sessionId} revoked`);
          return null;
        }

        if (session.replacedBySessionId) {
          logger.warn(`Session ${sessionId} rotated → reuse detected`);
          await revokeSessionChain(session);
          return null;
        }

        if (session.expiresAt < now) {
          logger.warn(`Session ${sessionId} expired`);
          return null;
        }

        if (session.idleExpiresAt < now) {
          logger.warn(`Session ${sessionId} idle timeout`);
          return null;
        }

        const user = await User.findOne({
          where: { id: userId, revoked: false },
        });
        return user ?? null;
      }
    }

    if (type === 'bearer') {
      const serviceSecret = await getSecret('ADMIN_SERVICE_TOKEN');

      try {
        payload = jwt.verify(value, serviceSecret, {
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

    return null;
  } catch (err) {
    console.error('[validateSession] failed:', err);
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
