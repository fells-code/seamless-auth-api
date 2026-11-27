/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { timingSafeEqual } from 'crypto';
import { importSPKI, jwtVerify } from 'jose';
import { literal, Op } from 'sequelize';

import {
  MAX_REFRESH_REPLAYS,
  openReplayToken,
  refreshReplayWindowMs,
} from '../lib/refreshReplayToken.js';
import { createRefreshTokenLookup } from '../lib/token.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { getPublicKeyByKid } from '../utils/signingKeyStore.js';
import { decoyPrincipalAsUser, decoyPrincipalForSubject } from './decoyPrincipal.js';
import { resolveCurrentSession } from './oidcAuthContext.js';
import { isRevokedByCutoff, PARENT_SESSION_ENDED } from './sessionRevocation.js';

const logger = getLogger('sessionService');

export type AuthTokenType = 'ephemeral' | 'access';

const ISSUER = process.env.ISSUER!;
const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export interface ValidatedAccessToken {
  userId: string;
  sessionId: string;
  roles: string[];
  organizationId: string | null;
}

/**
 * Verifies a token this server signed, and that it is the kind the caller expects.
 *
 * `either` exists for one caller, misuse detection, which needs to learn which kind a
 * token presented on the wrong route was. Everything that authorizes on a token names
 * the kind it accepts.
 */
export async function verifyJwtWithKid(token: string, expectedType: AuthTokenType | 'either') {
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
        audience: ISSUER,
        algorithms: ['RS256'],
      },
    );

    if (payload.typ !== 'access' && payload.typ !== 'ephemeral') {
      logger.warn(`JWT has no recognised typ: '${payload.typ}'`);
      return null;
    }

    if (expectedType !== 'either' && payload.typ !== expectedType) {
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
    // A row an earlier revoke already ended keeps the reason it was ended for.
    if (!current.revokedAt) {
      current.revokedAt = now;
      current.revokedReason = reason;
    }
    current.replayTokenCiphertext = null;
    await current.save();

    if (!current.replacedBySessionId) {
      // A rotation can claim the head between its read and the save above, and the save
      // leaves that link in place without this copy seeing it. Once saved as revoked the
      // head cannot be claimed again, so one reload settles where the chain ends.
      await current.reload();
      if (!current.replacedBySessionId) break;
    }
    current = await Session.findByPk(current.replacedBySessionId);
  }

  await revokeOrphanedChildSessions(session);
}

export async function hardRevokeSession(session: Session, reason = 'manual_revoke') {
  session.revokedAt = new Date();
  session.revokedReason = reason;
  await session.save();

  await revokeOrphanedChildSessions(session);
}

/**
 * The cascade that follows a session ending, for a user who holds exchanged sessions (ADR
 * 0003, X4). A child records the row its parent was on when it was exchanged, and the parent
 * rotates on from there, so which children just lost their parent is answered the same way
 * validation answers it: by following each child's link forward. This keeps session lists
 * accurate. It is not what ends a child, which is the check in `validateSessionRecord`, so a
 * failure here is logged rather than failing the revoke that caused it.
 */
export async function revokeOrphanedChildSessions(
  session: Pick<Session, 'userId' | 'parentSessionId'>,
) {
  if (session.parentSessionId) return;

  try {
    const children = await Session.findAll({
      where: {
        userId: session.userId,
        parentSessionId: { [Op.ne]: null },
        revokedAt: null,
        replacedBySessionId: null,
      },
    });

    for (const child of children) {
      if (await resolveCurrentSession(child.parentSessionId as string)) continue;

      await Session.update(
        { revokedAt: new Date(), revokedReason: PARENT_SESSION_ENDED },
        { where: { id: child.id, revokedAt: null } },
      );
    }
  } catch (error) {
    logger.error(`Could not revoke the child sessions of a session that ended: ${error}`);
  }
}

/**
 * Points a session at its replacement, but only while nothing else has claimed it.
 *
 * Rotation reads the session, checks it has not been rotated, creates the replacement and
 * writes this link, in four statements with nothing holding the answer still between
 * them. Two refreshes carrying the same token therefore both pass the check and both
 * write the link, and the second write wins: two working refresh tokens exist, and one
 * replacement is reachable from nothing, so the chain revocation that reuse detection
 * triggers walks straight past it. That is the case reuse detection exists for.
 *
 * The condition in the `where` is what decides a single winner, in one statement the
 * database serialises. No affected rows means another rotation got there first, which is
 * the same thing the reuse check answers `401` to.
 */
export async function claimSessionRotation(
  session: Session,
  replacementSessionId: string,
  replay?: { rotatedAt: Date; replayTokenCiphertext: string | null },
): Promise<boolean> {
  // The sealed successor token is written in the same statement as the link, so a request
  // that loses this race finds it there when it falls back to the replay window.
  const [claimed] = await Session.update(
    { replacedBySessionId: replacementSessionId, ...replay },
    { where: { id: session.id, replacedBySessionId: null, revokedAt: null } },
  );

  if (claimed === 0) {
    return false;
  }

  session.replacedBySessionId = replacementSessionId;
  if (replay) Object.assign(session, replay);

  return true;
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

function safeEqual(left: string, right: string | null) {
  if (!right) return false;

  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) return false;

  return timingSafeEqual(leftBuffer, rightBuffer);
}

/**
 * The session a refresh token belongs to, whatever state it is in. Expired, idled out,
 * revoked and rotated rows are all returned, because what the caller does next depends on
 * which: a rotated row is reuse however long ago it rotated, and that signal is lost if the
 * lookup filters it out first.
 */
export async function findRefreshSessionByToken(refreshToken: string): Promise<Session | null> {
  const refreshTokenLookup = createRefreshTokenLookup(refreshToken);

  const session = await Session.findOne({ where: { refreshTokenLookup } });

  if (!session) return null;

  // Re-checked outside the query. The database found the row by this value, but the
  // comparison there is the driver's, and this is the one that decides whether the
  // presented token is the session's. Constant time, so a near miss cannot be
  // distinguished from a far one by how long the answer takes.
  if (!safeEqual(refreshTokenLookup, session.refreshTokenLookup)) {
    logger.warn('Refresh token lookup matched a session whose fingerprint did not verify');
    return null;
  }

  return session;
}

export interface RefreshReplay {
  successor: Session;
  user: User;
  refreshToken: string;
}

/**
 * Answers a rotated refresh token with the successor it already rotated into, when it is
 * presented again within the replay window (#598). Two adapter instances refreshing the
 * same token at once otherwise read as reuse and sign the user out.
 *
 * Only the immediate predecessor of a live head qualifies, only inside the window and only
 * `MAX_REFRESH_REPLAYS` times, and the answer is the existing successor, never a new one.
 * `null` means the presentation is reuse.
 */
export async function replayRefreshRotation(
  session: Session,
  presentedToken: string,
  now = new Date(),
): Promise<RefreshReplay | null> {
  const windowMs = refreshReplayWindowMs();
  const { rotatedAt, replayTokenCiphertext, replacedBySessionId } = session;

  if (session.revokedAt || !replacedBySessionId || !rotatedAt || !replayTokenCiphertext) {
    return null;
  }

  if (windowMs === 0 || now.getTime() - new Date(rotatedAt).getTime() > windowMs) {
    await Session.update({ replayTokenCiphertext: null }, { where: { id: session.id } });
    return null;
  }

  // Also refuses a successor that has itself rotated, so an older ancestor is never answered.
  const successor = await validateSessionRecord(replacedBySessionId);
  if (!successor) return null;

  const refreshToken = openReplayToken(
    { predecessorToken: presentedToken, predecessorId: session.id, successorId: successor.id },
    replayTokenCiphertext,
  );

  if (
    !refreshToken ||
    !safeEqual(createRefreshTokenLookup(refreshToken), successor.refreshTokenLookup)
  ) {
    logger.warn(`Replay token for session ${session.id} did not open to its successor`);
    return null;
  }

  const user = await getUserFromSession(successor);
  if (!user) return null;

  // Counted in the database, so concurrent replays cannot all read the same count and
  // each spend the last one.
  const [claimed] = await Session.update(
    { replayCount: literal('"replayCount" + 1') },
    {
      where: {
        id: session.id,
        revokedAt: null,
        replacedBySessionId: successor.id,
        replayCount: { [Op.lt]: MAX_REFRESH_REPLAYS },
        rotatedAt: { [Op.gt]: new Date(now.getTime() - windowMs) },
      },
    },
  );

  if (claimed === 0) return null;

  return { successor, user, refreshToken };
}

export async function validateSessionRecord(sessionId: string) {
  const session = await Session.findByPk(sessionId);
  if (!session) return null;

  const now = new Date();

  if (session.revokedAt) return null;

  // A rotated session is simply no longer current, so its access token stops being
  // accepted. It is not reuse: the previous access token stays valid until it expires,
  // so an in-flight request that raced the refresh, or a second tab, legitimately
  // arrives holding it. Revoking the chain here followed replacedBySessionId forward
  // into the session that was just issued and signed the user out everywhere. Refresh
  // token reuse is still detected, in refreshSession, where the reused credential is
  // the refresh token itself.
  if (session.replacedBySessionId) return null;

  if (session.expiresAt < now) return null;
  if (session.idleExpiresAt < now) return null;

  // Catches a session that a revoke-all missed because a refresh created it mid-revoke.
  const owner = await User.findOne({
    where: { id: session.userId },
    attributes: ['id', 'sessionsRevokedBefore'],
  });
  if (!owner || isRevokedByCutoff(session, owner.sessionsRevokedBefore)) return null;

  // An exchanged session ends with its parent whether or not a revoke's cascade reached it,
  // and the parent also ends without any revoke when it expires or idles out (ADR 0003, X4).
  if (session.parentSessionId && !(await resolveCurrentSession(session.parentSessionId))) {
    return null;
  }

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
  /** The ephemeral token's `jti`, absent on tokens minted before it was set. */
  attemptId?: string;
  /** The ephemeral token's `exp`, which a re-minted token for the same attempt keeps. */
  attemptExpiresAt?: number;
  /** An access session a recovery issued, restricted until a new factor is enrolled. */
  recovery?: boolean;
  /** The step-up state of a session exchanged from a device grant (ADR 0003, X7). */
  deviceChildSession?: Pick<Session, 'stepUpVerifiedAt' | 'stepUpMethod'>;
}

export async function validateEphemeralToken(token: string): Promise<ValidatedBearerToken | null> {
  const payload = await verifyJwtWithKid(token, 'ephemeral');

  if (!payload || typeof payload.sub !== 'string') {
    return null;
  }

  const attempt = {
    ...(typeof payload.jti === 'string' ? { attemptId: payload.jti } : {}),
    ...(typeof payload.exp === 'number' ? { attemptExpiresAt: payload.exp } : {}),
  };

  const user = await User.findOne({
    where: { id: payload.sub, revoked: false },
  });

  if (user) {
    return { user, ...attempt };
  }

  // The signature, issuer, audience, type and expiry have all already been checked, so
  // this token was minted here. A subject that resolves to no row is therefore the
  // decoy `/login` issued for an identifier with no usable account, and the request
  // continues as that fiction rather than being rejected. Rejecting here is what used
  // to move the oracle one request later.
  //
  // A token whose user was deleted or revoked mid-flow lands here too, and is likewise
  // answered as a decoy rather than with a distinguishable 401.
  return {
    user: decoyPrincipalAsUser(decoyPrincipalForSubject(payload.sub)),
    decoy: true,
    ...attempt,
  };
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
        // Read from the session rather than the token: enrolling a factor clears it on
        // the row, which takes effect at once, before the client next refreshes.
        recovery: session.recovery === true,
        ...(session.exchangeGrantType === DEVICE_CODE_GRANT
          ? {
              deviceChildSession: {
                stepUpVerifiedAt: session.stepUpVerifiedAt,
                stepUpMethod: session.stepUpMethod,
              },
            }
          : {}),
      }
    : null;
}
