/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { compareSync } from 'bcrypt-ts';
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig';
import { clearAuthCookies, setAuthCookies } from '../lib/cookie';
import {
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
  signEphemeralToken,
} from '../lib/token';
import { AuthEvent } from '../models/authEvents';
import { Credential } from '../models/credentials';
import { Session } from '../models/sessions';
import { User } from '../models/users';
import { AuthEventService } from '../services/authEventService';
import { hardRevokeSession, revokeSessionChain } from '../services/sessionService';
import { AuthenticatedRequest } from '../types/types';
import getLogger from '../utils/logger';
import { getSecret } from '../utils/secretsStore';
import {
  computeSessionTimes,
  isValidEmail,
  isValidPhoneNumber,
  parseDurationToSeconds,
} from '../utils/utils';

const logger = getLogger('authentication');
const AUTH_MODE = process.env.AUTH_MODE;

export const login = async (req: Request, res: Response) => {
  // For the initial login step, user either passes in an email or a phone number
  const { identifier } = req.body;
  let user, identifierType;

  if (!identifier) {
    logger.warn('No pre authenticated identifier found');
    await AuthEvent.create({
      user_id: null,
      type: 'login_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'No identifier supplied' },
    });
    return res.status(403).json({ message: 'Not allowed' });
  }

  logger.info(`Login attempt with ${identifier}`);

  try {
    if (isValidEmail(identifier)) {
      try {
        user = await User.findOne({
          where: { email: identifier.toLowerCase() },
        });
        identifierType = 'email';
      } catch {
        logger.error('Failed to find user');
        await AuthEvent.create({
          user_id: null,
          type: 'login_failed',
          ip_address: req.ip,
          user_agent: req.headers['user-agent'],
          metadata: { reason: `No user found for identifer: ${identifier}` },
        });
        return res.status(401).json({ message: 'Not allowed' });
      }
    } else if (isValidPhoneNumber(identifier)) {
      try {
        user = await User.findOne({
          where: { phone: identifier },
        });
        identifierType = 'phone';
      } catch {
        logger.error('Failed to find user');
        await AuthEvent.create({
          user_id: null,
          type: 'login_failed',
          ip_address: req.ip,
          user_agent: req.headers['user-agent'],
          metadata: { reason: `No user found for identifer: ${identifier}` },
        });
        return res.status(403).json({ message: 'Not allowed' });
      }
    } else {
      logger.error(`Invalid identifier: ${identifier}`);
      await AuthEvent.create({
        user_id: null,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: `No user found for identifer: ${identifier}` },
      });
      return res.status(400).json({ message: 'Invalid data' });
    }
  } catch (error) {
    logger.error(`Failed to find a user with valid Identifier: ${error}`);
    await AuthEvent.create({
      user_id: null,
      type: 'login_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: `No user found for identifer: ${identifier}` },
    });
    return res.status(500).json({ message: 'Internal server error' });
  }

  try {
    if (!user) {
      logger.error(`Login attempt failed for non-existent identity: ${identifier}`);
      await AuthEvent.create({
        user_id: null,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: `No user found for identifer: ${identifier}` },
      });
      return res.status(401).json({ message: 'Not Allowed' });
    }

    // pre-auth token
    const token = await signEphemeralToken(user.id);

    if (!user.verified) {
      logger.warn(`Login attempt for unverified account: ${identifier}`);
      await AuthEvent.create({
        user_id: user.id,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: `Unverified but valid user` },
      });

      return res.status(401).json({ message: 'Login failed. Need to verify.' });
    }

    const credential = await Credential.findOne({ where: { userId: user.id } });

    if (!credential) {
      logger.error(`Login attempt for a verified users, but no passkey. ${identifier}`);
      await AuthEvent.create({
        user_id: user.id,
        type: 'login_failed',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: { reason: `No credentials ${identifier}` },
      });
      return res.status(401).json({ message: 'Need to re-register and create passkey' });
    }

    if (token) {
      await AuthEvent.create({
        user_id: user.id,
        type: 'login_success',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        metadata: {},
      });

      if (AUTH_MODE === 'web') {
        await setAuthCookies(res, { ephemeralToken: token });
        res.status(200).json({ message: 'Success' });
        return;
      }

      const { access_token_ttl } = await getSystemConfig();
      return res.status(200).json({
        message: 'Success',
        sub: user.id,
        token,
        identifierType,
        ttl: parseDurationToSeconds(access_token_ttl || '15m'),
      });
    }
    return res.status(401).json({ message: 'Login failed.' });
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error during login for email ${error.message}`);
    } else {
      logger.error(`Failed to login - ${String(error)}`);
    }

    await AuthEvent.create({
      user_id: null,
      type: 'login_failed',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      metadata: { reason: 'Catch all error' },
    });
    return res.status(500).json({ message: 'Server error' });
  }
};

export const logout = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;
  logger.info(`${authUser?.email} logged out.`);

  try {
    const sessions = await Session.findAll({ where: { userId: authUser.id } });

    sessions.forEach(async (session) => {
      if (!session.revokedAt) {
        await hardRevokeSession(session, 'user_logout');
      }
    });

    await AuthEventService.log({ userId: authUser.id, type: 'logout_success', req });
  } catch (error) {
    logger.error(`Error during logout: ${error}`);
    await AuthEventService.log({ userId: authUser.id, type: 'logout_failed', req });
  } finally {
    clearAuthCookies(res);
  }

  return res.json({ message: 'Success' });
};

export const refreshSession = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;
  logger.info(`Refreshing user token`);

  let refreshToken;

  refreshToken = req.headers['authorization']?.toString().startsWith('Bearer ')
    ? req.headers['authorization']!.slice('Bearer '.length)
    : null;

  if (!refreshToken) {
    return res.status(401).json('Not allowed');
  }

  const serviceSecret = await getSecret('API_SERVICE_TOKEN');

  const payload = jwt.verify(refreshToken, serviceSecret, {
    issuer: process.env.APP_ORIGIN,
    audience: process.env.ISSUER,
  }) as jwt.JwtPayload;

  if (!refreshToken) {
    logger.error('Refresh token provided is not of expected type for auth server configurations');
    await AuthEventService.log({
      userId: authUser.id,
      type: 'bearer_token_suspicious',
      req,
      metadata: { reason: 'Missing all required headers and tokens needed to perform a refresh' },
    });
    res.status(401).json({ error: 'Missing refresh token parameters' });
    return;
  }

  const now = new Date();

  // Find session that is not revoked, not replaced, and not expired
  const candidateSessions = await Session.findAll({
    where: {
      revokedAt: null,
      expiresAt: { [Op.gt]: now },
      idleExpiresAt: { [Op.gt]: now },
    },
  });

  let session: Session | null = null;
  for (const s of candidateSessions) {
    const match = await compareSync(payload.refreshToken, s.refreshTokenHash);
    if (match) {
      session = s;
      break;
    }
  }

  if (!session) {
    logger.warn('No refresh session found for refresh token');
    await AuthEventService.serviceTokenInvalid(req);
    return res.status(401).json({ error: 'invalid_refresh_token' });
  }

  // Reuse detection: if this session was already rotated, it means we’ve seen this token before
  if (session.replacedBySessionId || session.revokedAt) {
    logger.warn('Token reuse detected');
    // Reuse -> revoke session chain
    await revokeSessionChain(session);
    // Log security event
    return res.status(401).json({ error: 'refresh_token_reused' });
  }

  // Update idle timeout on current session (just for bookkeeping)
  session.lastUsedAt = now;
  await session.save();

  const user = await User.findByPk(session.userId);
  if (!user) {
    await hardRevokeSession(session, 'user_not_found');
    return res.status(401).json({ error: 'invalid_session' });
  }

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
  await session.save();

  const token = await signAccessToken(session.id, user.id);

  if (token && newRefreshTokenHash) {
    await AuthEventService.log({ userId: user.id, type: 'refresh_token_success', req });

    if (AUTH_MODE === 'web') {
      await setAuthCookies(res, { accessToken: token, refreshToken: newRefreshToken });
      res.status(200).json({ message: 'Success' });
      return;
    }

    const { access_token_ttl, refresh_token_ttl } = await getSystemConfig();
    return res.status(200).json({
      message: 'Success',
      token,
      refreshToken: newRefreshTokenHash,
      sub: user.id,
      ttl: parseDurationToSeconds(access_token_ttl || '15m'),
      refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1h'),
    });
  }
};
