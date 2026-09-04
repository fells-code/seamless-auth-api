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
import {
  DecoyIdentifierType,
  decoyPrincipalForSubject,
  decoySubjectFor,
} from '../services/decoyPrincipal.js';
import { rejectIfUserLocked } from '../services/lockoutPolicyService.js';
import {
  getLoginPolicy,
  LoginMethod,
  resolveAvailableLoginMethods,
} from '../services/loginPolicyService.js';
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
 * How long `/login` takes at minimum, in milliseconds.
 *
 * The real path reads the users table, the lockout counter, the credentials table and
 * the login policy. The decoy path reads only the policy. Left alone, that difference is
 * an oracle in its own right: identical bodies that arrive at measurably different times
 * still answer the question. Holding every answer until a floor removes the difference
 * as long as both paths finish under it.
 *
 * An environment variable rather than a `system_config` key on purpose. The config schema
 * is shared through `@seamless-auth/types`, so a key there means a coordinated release
 * across both SDKs for what is an operational tuning knob, not a policy a deployment
 * changes at runtime.
 *
 * Set it above the slowest real login the deployment sees. Set it to `0` to turn the
 * floor off, which the test suite does so that it is exercised deliberately in one place
 * rather than paid for in every login test.
 */
function loginResponseFloorMs() {
  const configured = Number(process.env.LOGIN_RESPONSE_FLOOR_MS);

  return Number.isFinite(configured) && configured >= 0 ? configured : 250;
}

async function holdUntilFloor(startedAt: number) {
  const remaining = loginResponseFloorMs() - (Date.now() - startedAt);

  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}

/**
 * The pre-auth answer `/login` gives, for a real account and for a decoy alike.
 *
 * There is one response builder rather than two so the shapes cannot drift apart. A
 * field added to one and forgotten in the other is exactly the tell this closes.
 */
async function respondWithPreAuth({
  res,
  startedAt,
  subject,
  identifierType,
  loginMethods,
}: {
  res: Response;
  startedAt: number;
  subject: string;
  identifierType: string;
  loginMethods: LoginMethod[];
}) {
  const token = await signEphemeralToken(subject);

  // Signing normally throws rather than returning empty. Treating a falsy token as a
  // server fault keeps the decoy and the real path failing the same way, instead of one
  // of them answering 200 with a token field the caller cannot use.
  if (!token) {
    throw new Error('Failed to sign the pre-auth token');
  }

  const { access_token_ttl } = await getSystemConfig();

  await holdUntilFloor(startedAt);

  return res.status(200).json({
    message: 'Success',
    sub: subject,
    token,
    identifierType,
    loginMethods,
    ttl: parseDurationToSeconds(access_token_ttl || '15m'),
  });
}

/**
 * The answer for an identifier that resolves to no usable account.
 *
 * Previously a `401` with one identical body, which still separated "this account exists
 * and can sign in" from everything else. Now a decoy: a stable, unguessable subject
 * derived from the identifier, a real ephemeral token signed over it, and the method list
 * the policy permits. The reason survives in the auth event for operators.
 *
 * The decoy only holds because every ephemeral endpoint answers for it; see
 * `decoyResponders.ts` and the registration-time check in `defineRoute`.
 */
async function respondWithDecoy({
  req,
  res,
  startedAt,
  identifier,
  identifierType,
  userId,
  reason,
  passkeyAvailable,
}: {
  req: Request;
  res: Response;
  startedAt: number;
  identifier: string;
  identifierType: DecoyIdentifierType;
  userId: string | null;
  reason: string;
  passkeyAvailable?: boolean;
}) {
  await AuthEventService.log({
    userId,
    type: 'login_failed',
    req,
    metadata: { reason, decoy: true },
  });

  const subject = decoySubjectFor(identifier, identifierType);
  const principal = decoyPrincipalForSubject(subject);
  const policy = await getLoginPolicy();

  return respondWithPreAuth({
    res,
    startedAt,
    subject,
    identifierType,
    // A decoy is treated as fully provisioned, so the offered methods are whatever the
    // deployment permits. Deriving them from account state instead would put the answer
    // back in the response.
    loginMethods: resolveAvailableLoginMethods({
      policy,
      user: principal,
      hasPasskeyCredential: true,
      passkeyAvailable,
    }),
  });
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
  const startedAt = Date.now();
  // For the initial login step, user either passes in an email or a phone number
  const { identifier, passkeyAvailable } = req.body;
  let user, identifierType: DecoyIdentifierType | undefined;
  // The normal form the account was looked up under, which is also what the decoy
  // subject derives from, so two spellings of one identifier cannot be told apart.
  let decoyIdentifier: string;
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
      decoyIdentifier = identifier.toLowerCase();
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
      decoyIdentifier = normalizedIdentifier;
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
      return await respondWithDecoy({
        req,
        res,
        startedAt,
        identifier: decoyIdentifier,
        identifierType: identifierType!,
        userId: null,
        reason: 'No user found for identifier',
        passkeyAvailable,
      });
    }

    if (await rejectIfUserLocked({ userId: user.id, req, res })) {
      return;
    }

    if (!user.verified) {
      logger.warn('Login attempt for unverified account');
      return await respondWithDecoy({
        req,
        res,
        startedAt,
        identifier: decoyIdentifier,
        identifierType: identifierType!,
        userId: user.id,
        reason: 'Unverified but valid user',
        passkeyAvailable,
      });
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
      return await respondWithDecoy({
        req,
        res,
        startedAt,
        identifier: decoyIdentifier,
        identifierType: identifierType!,
        userId: user.id,
        reason: 'No allowed login methods available',
        passkeyAvailable,
      });
    }

    await AuthEventService.log({
      userId: user.id,
      type: 'login_success',
      req,
      metadata: {},
    });

    return await respondWithPreAuth({
      res,
      startedAt,
      subject: user.id,
      identifierType: identifierType!,
      loginMethods,
    });
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

  const { access_token_ttl, refresh_token_ttl, session_idle_ttl } = await getSystemConfig();
  const { expiresAt, idleExpiresAt } = computeSessionTimes(
    { absoluteTtl: refresh_token_ttl || '1d', idleTtl: session_idle_ttl || '8h' },
    now,
  );
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
      refreshTtl: parseDurationToSeconds(refresh_token_ttl || '1d'),
    });
  }

  return res.status(500).json({ error: 'Failed to refresh session' });
};
