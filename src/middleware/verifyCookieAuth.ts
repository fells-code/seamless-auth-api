/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { compareSync } from 'bcrypt-ts';
import { NextFunction, Request, Response } from 'express';
import { Op } from 'sequelize';

import { clearAuthCookies, setAuthCookies } from '../lib/cookie';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../lib/token';
import { Session } from '../models/sessions';
import { User } from '../models/users';
import { AuthEventService } from '../services/authEventService';
import {
  CookieType,
  hardRevokeSession,
  revokeSessionChain,
  validateSession,
} from '../services/sessionService';
import { AuthenticatedRequest } from '../types/types';
import getLogger from '../utils/logger';
import { computeSessionTimes } from '../utils/utils';

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
        logger.debug(`Validating ephemeral cookie`);
        const user = await validateSession({
          type: 'cookie',
          value: ephemeralCookie,
          cookieType: 'ephemeral',
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
        const user = await validateSession({
          type: 'cookie',
          value: accessCookie,
          cookieType: 'access',
        });

        if (user) {
          (req as AuthenticatedRequest).user = user;
          return next();
        }
      }

      // Access token missing or invalid, try silent refresh
      const refreshedUser = await performSilentRefresh(req, res);

      if (refreshedUser) {
        (req as AuthenticatedRequest).user = refreshedUser;
        return next();
      }

      // If we reach here, both access & refresh failed
      clearAuthCookies(res);
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

  // Find candidate sessions for this refresh token
  const candidateSessions = await Session.findAll({
    where: {
      revokedAt: null,
      expiresAt: { [Op.gt]: now },
      idleExpiresAt: { [Op.gt]: now },
    },
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
