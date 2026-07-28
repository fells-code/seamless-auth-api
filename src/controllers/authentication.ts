/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
  signEphemeralToken,
} from '../lib/token.js';
import { Credential } from '../models/credentials.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import { AuthEventService } from '../services/authEventService.js';
import { rejectIfUserLocked } from '../services/lockoutPolicyService.js';
import { getLoginPolicy, resolveAvailableLoginMethods } from '../services/loginPolicyService.js';
import {
  findRefreshSessionByToken,
  hardRevokeSession,
  revokeSessionChain,
} from '../services/sessionService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import {
  computeSessionTimes,
  isValidEmail,
  isValidPhoneNumber,
  normalizePhoneNumber,
  parseDurationToSeconds,
} from '../utils/utils.js';

const logger = getLogger('authentication');

/**
 * The single rejection every failed `/login` takes, whatever the reason.
 *
 * An unknown identifier, an unverified account, and an account with no permitted
 * continuation method used to answer with three distinguishable bodies, which told an
 * unauthenticated caller which of the three it had hit. The reason is still recorded as
 * auth-event metadata for operators; it is just no longer disclosed to the caller.
 *
 * This does not make `/login` non-enumerable on its own: a valid identifier still gets a
 * 200 with an ephemeral token. Closing that requires decoy tokens across the continuation
 * endpoints. See docs/security-posture.md.
 */
function rejectLogin(res: Response) {
  return res.status(401).json({ error: 'Not Allowed' });
}

/**
 * The identifier lookup threw, meaning the database is unreachable rather than the
 * identifier being unknown. The email branch answered 401 and the phone branch 403 for
 * the same failure, which is what automated scans flag on this handler. Both now report
 * a server error, so an outage is not reported to the caller as a failed login.
 */
function rejectLoginLookupFailure(res: Response) {
  return res.status(500).json({ error: 'Server error' });
}

export const login = async (req: Request, res: Response) => {
  // For the initial login step, user either passes in an email or a phone number
  const { identifier, passkeyAvailable } = req.body;
  let user, identifierType;
  const normalizedIdentifier =
    typeof identifier === 'string' && isValidPhoneNumber(identifier)
      ? normalizePhoneNumber(identifier)
      : null;

  if (!identifier) {
    logger.warn('No pre authenticated identifier found');
    await AuthEventService.log({
      userId: null,
      type: 'login_failed',
      req,
      metadata: { reason: 'No identifier supplied' },
    });
    return res.status(403).json({ error: 'Not allowed' });
  }

  logger.info('Login attempt with identifier');

  if (isValidEmail(identifier)) {
    try {
      user = await User.findOne({
        where: { email: identifier.toLowerCase() },
      });
      identifierType = 'email';
    } catch {
      logger.error('Failed to look up user by email');
      await AuthEventService.log({
        userId: null,
        type: 'login_failed',
        req,
        metadata: { reason: 'Identifier lookup failed' },
      });
      return rejectLoginLookupFailure(res);
    }
  } else if (isValidPhoneNumber(identifier) && normalizedIdentifier) {
    try {
      user = await User.findOne({
        where: { phone: normalizedIdentifier },
      });
      identifierType = 'phone';
    } catch {
      logger.error('Failed to look up user by phone');
      await AuthEventService.log({
        userId: null,
        type: 'login_failed',
        req,
        metadata: { reason: 'Identifier lookup failed' },
      });
      return rejectLoginLookupFailure(res);
    }
  } else {
    logger.error('Invalid login identifier');
    await AuthEventService.log({
      userId: null,
      type: 'login_failed',
      req,
      metadata: { reason: 'Invalid identifier' },
    });
    return res.status(400).json({ error: 'Invalid data' });
  }

  try {
    if (!user) {
      logger.error('Login attempt failed for non-existent identity');
      await AuthEventService.log({
        userId: null,
        type: 'login_failed',
        req,
        metadata: { reason: 'No user found for identifier' },
      });
      return rejectLogin(res);
    }

    if (await rejectIfUserLocked({ userId: user.id, req, res })) {
      return;
    }

    // pre-auth token
    const token = await signEphemeralToken(user.id);

    if (!user.verified) {
      logger.warn('Login attempt for unverified account');
      await AuthEventService.log({
        userId: user.id,
        type: 'login_failed',
        req,
        metadata: { reason: 'Unverified but valid user' },
      });

      return rejectLogin(res);
    }

    const [credential, loginPolicy] = await Promise.all([
      Credential.findOne({ where: { userId: user.id } }),
      getLoginPolicy(),
    ]);
    const loginMethods = resolveAvailableLoginMethods({
      policy: loginPolicy,
      user,
      hasPasskeyCredential: Boolean(credential),
      passkeyAvailable,
    });

    if (loginMethods.length === 0) {
      logger.error('Login attempt had no allowed continuation methods');
      await AuthEventService.log({
        userId: user.id,
        type: 'login_failed',
        req,
        metadata: { reason: 'No allowed login methods available' },
      });
      return rejectLogin(res);
    }

    if (token) {
      await AuthEventService.log({
        userId: user.id,
        type: 'login_success',
        req,
        metadata: {},
      });

      const { access_token_ttl } = await getSystemConfig();
      return res.status(200).json({
        message: 'Success',
        sub: user.id,
        token,
        identifierType,
        loginMethods,
        ttl: parseDurationToSeconds(access_token_ttl || '15m'),
      });
    }
    return rejectLogin(res);
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(`Error during login: ${error.message}`);
    } else {
      logger.error(`Failed to login - ${String(error)}`);
    }

    await AuthEventService.log({
      userId: null,
      type: 'login_failed',
      req,
      metadata: { reason: 'Catch all error' },
    });
    return res.status(500).json({ error: 'Server error' });
  }
};

export const logoutCurrentSession = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;
  const sessionId = authReq.sessionId;
  logger.info('User logged out current session');

  try {
    if (!sessionId) {
      await AuthEventService.log({
        userId: authUser.id,
        type: 'logout_suspicious',
        req,
        metadata: { reason: 'Access token did not include a session id' },
      });
      return res.status(401).json({ error: 'unauthorized' });
    }

    const session = await Session.findOne({
      where: { id: sessionId, userId: authUser.id, revokedAt: null },
    });

    if (session) {
      await hardRevokeSession(session, 'user_logout');
    }

    await AuthEventService.log({
      userId: authUser.id,
      type: 'logout_success',
      req,
      metadata: { scope: 'current_session' },
    });
  } catch (error) {
    logger.error(`Error during logout: ${error}`);
    await AuthEventService.log({ userId: authUser.id, type: 'logout_failed', req });
  }

  return res.json({ message: 'Success' });
};

export const logoutAllSessions = async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const authUser = authReq.user;
  logger.info('User logged out all sessions');

  try {
    const sessions = await Session.findAll({ where: { userId: authUser.id, revokedAt: null } });

    await Promise.all(sessions.map((session) => hardRevokeSession(session, 'user_logout_all')));

    await AuthEventService.log({
      userId: authUser.id,
      type: 'logout_success',
      req,
      metadata: { scope: 'all_sessions', revokedSessions: sessions.length },
    });
  } catch (error) {
    logger.error(`Error during logout: ${error}`);
    await AuthEventService.log({ userId: authUser.id, type: 'logout_failed', req });
  }

  return res.json({ message: 'Success' });
};

export const logout = logoutAllSessions;

export const refreshSession = async (req: Request, res: Response) => {
  logger.info(`Refreshing user token`);

  let refreshToken: string | null = null;

  if (req.headers.authorization?.startsWith('Bearer ')) {
    refreshToken = req.headers.authorization.slice('Bearer '.length);
  }

  if (!refreshToken) {
    logger.error('Refresh token provided is not of expected type for auth server configurations');
    await AuthEventService.refreshTokenFailed(req, { reason: 'Missing refresh token' });
    res.status(401).json({ error: 'Not allowed' });
    return;
  }

  const now = new Date();
  const session = await findRefreshSessionByToken(refreshToken, now);

  if (!session) {
    const looksLikeJwt = refreshToken.split('.').length === 3;

    logger.warn(
      `No refresh session found for refresh token. tokenFormat=${looksLikeJwt ? 'jwt_like' : 'opaque'}`,
    );

    if (looksLikeJwt) {
      logger.warn(
        'Refresh endpoint received a JWT-shaped bearer token. Server-mode /refresh expects the raw opaque refresh token, not the access token.',
      );
    }

    await AuthEventService.refreshTokenFailed(req, {
      reason: 'No refresh session found for refresh token',
      tokenFormat: looksLikeJwt ? 'jwt_like' : 'opaque',
    });
    return res.status(401).json({ error: 'invalid_refresh_token' });
  }

  // Reuse detection: if this session was already rotated, it means we’ve seen this token before
  if (session.replacedBySessionId || session.revokedAt) {
    logger.warn(
      `Token reuse detected for session ${session.id}. replacedBySessionId=${session.replacedBySessionId ?? 'none'} revokedAt=${session.revokedAt ? session.revokedAt.toISOString() : 'null'}. This usually means an already-rotated refresh token was sent again.`,
    );
    // Reuse -> revoke session chain
    await revokeSessionChain(session);
    await AuthEventService.log({
      userId: session.userId,
      type: 'refresh_token_suspicious',
      req,
      metadata: {
        reason: 'Refresh token reuse detected',
        sessionId: session.id,
        replacedBySessionId: session.replacedBySessionId,
        revokedAt: session.revokedAt?.toISOString() ?? null,
      },
    });
    return res.status(401).json({ error: 'refresh_token_reused' });
  }

  // Update idle timeout on current session (just for bookkeeping)
  session.lastUsedAt = now;
  await session.save();

  const user = await User.findByPk(session.userId);
  if (!user) {
    await AuthEventService.log({
      userId: session.userId,
      type: 'refresh_token_suspicious',
      req,
      metadata: {
        reason: 'Refresh session user not found',
        sessionId: session.id,
      },
    });
    await hardRevokeSession(session, 'user_not_found');
    return res.status(401).json({ error: 'invalid_session' });
  }

  const { expiresAt, idleExpiresAt } = computeSessionTimes(now);
  const newRefreshToken = generateRefreshToken();
  const newRefreshTokenHash = await hashRefreshToken(newRefreshToken);
  const newRefreshTokenLookup = createRefreshTokenLookup(newRefreshToken);

  const newSession = await Session.create({
    userId: user.id,
    infraId: session.infraId,
    mode: 'server',
    organizationId: session.organizationId,
    refreshTokenHash: newRefreshTokenHash,
    refreshTokenLookup: newRefreshTokenLookup,
    userAgent: session.userAgent,
    ipAddress: req.ip,
    expiresAt,
    idleExpiresAt,
  });

  session.replacedBySessionId = newSession.id;
  await session.save();

  const token = await signAccessToken(newSession.id, user.id, user.roles, session.organizationId);

  if (token && newRefreshToken) {
    logger.info(
      `Refresh token rotated for user ${user.id}. oldSessionId=${session.id} newSessionId=${newSession.id}`,
    );
    await AuthEventService.log({ userId: user.id, type: 'refresh_token_success', req });

    const { access_token_ttl, refresh_token_ttl } = await getSystemConfig();
    return res.status(200).json({
      message: 'Success',
      token,
      refreshToken: newRefreshToken,
      sub: user.id,
      sessionId: newSession.id,
      organizationId: session.organizationId,
      roles: user.roles,
      email: user.email,
      phone: user.phone,
      ttl: parseDurationToSeconds(access_token_ttl || '15m'),
      refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1h'),
    });
  }

  return res.status(500).json({ error: 'Failed to refresh session' });
};
