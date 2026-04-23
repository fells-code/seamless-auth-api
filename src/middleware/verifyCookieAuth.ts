/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { compareSync } from 'bcrypt-ts';
import { NextFunction, Request, Response } from 'express';
import { Op } from 'sequelize';

import { clearAuthCookies, setAuthCookies } from '../lib/cookie.js';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../lib/token.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  CookieType,
  getUserFromSession,
  hardRevokeSession,
  revokeSessionChain,
  validateAccessToken,
  validateSessionRecord,
  verifyJwtWithKid,
} from '../services/sessionService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import { computeSessionTimes } from '../utils/utils.js';

const logger = getLogger('verify-cookie');

export function verifyCookieAuth(cookieType: CookieType = 'access') {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cookies = req.cookies || {};

      if (cookieType === 'ephemeral') {
        const ephemeralCookie = cookies['seamless_ephemeral'];

        if (!ephemeralCookie) {
          clearAuthCookies(res);
          return res.status(401).json({ error: 'unauthorized' });
        }

        const payload = await verifyJwtWithKid(ephemeralCookie, cookieType);
        if (!payload) {
          clearAuthCookies(res);
          return res.status(401).json({ error: 'unauthorized' });
        }

        const user = await User.findOne({
          where: { id: payload.sub, revoked: false },
        });

        if (!user) {
          clearAuthCookies(res);
          return res.status(401).json({ error: 'unauthorized' });
        }

        (req as AuthenticatedRequest).user = user;
        return next();
      }

      const accessCookie = cookies['seamless_access'];

      // Try validating existing access token first
      if (accessCookie) {
        logger.debug(`Validating access cookie`);
        const accessCookie = cookies['seamless_access'];

        if (accessCookie) {
          const tokenData = await validateAccessToken(accessCookie);

          if (tokenData) {
            const session = await validateSessionRecord(tokenData.sessionId as string);

            if (session) {
              const user = await getUserFromSession(session);

              if (user) {
                (req as AuthenticatedRequest).user = user;
                return next();
              }
            }
          }
        }
      }

      // Access token missing or invalid, try silent refresh
      const refreshedUser = await performSilentRefresh(req, res);

      if (refreshedUser) {
        (req as AuthenticatedRequest).user = refreshedUser;
        return next();
      }

      // If we reach here, both access & refresh failed
      //clearAuthCookies(res);
      return res.status(401).json({ error: 'unauthorized' });
    } catch (err) {
      logger.error('verifyCookieAuth error:', err);
      clearAuthCookies(res);
      return res.status(401).json({ error: 'unauthorized' });
    }
  };
}

async function performSilentRefresh(req: Request, res: Response): Promise<User | null> {
  const cookies = req.cookies || {};
  const refreshToken = cookies['seamless_refresh'];

  if (!refreshToken) {
    logger.debug('No refresh cookie present for silent refresh');
    return null;
  }

  const now = new Date();
  logger.debug(`Validating refresh cookie`);

  const candidateSessions = await Session.findAll({
    where: {
      revokedAt: null,
      expiresAt: { [Op.gt]: now },
      idleExpiresAt: { [Op.gt]: now },
    },
    limit: 50,
  });

  let session: Session | null = null;

  for (const s of candidateSessions) {
    if (compareSync(refreshToken, s.refreshTokenHash)) {
      session = s;
      break;
    }
  }

  if (!session) {
    logger.warn('No matching session found for refresh token');
    await AuthEventService.serviceTokenInvalid(req);
    return null;
  }

  // Reuse detection
  if (session.replacedBySessionId || session.revokedAt) {
    logger.warn('Refresh token reuse detected');
    await revokeSessionChain(session);
    await AuthEventService.serviceTokenInvalid(req);
    return null;
  }

  // Confirm user
  const user = await User.findByPk(session.userId);
  if (!user) {
    logger.warn(`Mismatched users from a refresh token and session. Logging supicious activity.`);
    AuthEventService.log({
      userId: session.userId,
      type: 'refresh_token_suspicious',
      req,
      metadata: { reason: 'Refresh token user id did not match session user id.' },
    });
    await hardRevokeSession(session, 'user_not_found');
    return null;
  }

  // Log refresh attempt
  logger.info(`User token refreshed.`);
  await AuthEventService.log({
    userId: user.id,
    type: 'informational',
    req,
    metadata: { reason: 'Web silent refresh' },
  });

  const { expiresAt, idleExpiresAt } = computeSessionTimes(now);

  const newRefreshToken = generateRefreshToken();
  const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);

  const newSession = await Session.create({
    userId: user.id,
    infraId: session.infraId,
    mode: session.mode,
    refreshTokenHash: newRefreshTokenHash,
    userAgent: session.userAgent,
    ipAddress: req.ip,
    expiresAt,
    idleExpiresAt,
  });

  session.replacedBySessionId = newSession.id;
  session.lastUsedAt = now;
  await session.save();

  const accessToken = await signAccessToken(newSession.id, user.id);

  await setAuthCookies(res, {
    accessToken,
    refreshToken: newRefreshToken,
  });

  await AuthEventService.log({
    userId: user.id,
    type: 'refresh_token_success',
    req,
  });

  return user;
}
