/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { randomBytes, randomInt } from 'crypto';
import { Op } from 'sequelize';

import {
  AccountRecoveryRequest,
  RecoveryChannel,
  StoredRecoveryState,
} from '../models/accountRecoveryRequests.js';
import { AuthFailure } from '../models/authFailures.js';
import getLogger from '../utils/logger.js';
import { generateRandomEmailOTP, hashOtpToken, otpHashMatches } from '../utils/otp.js';
import { hashSha256 } from '../utils/utils.js';
import { revokeAllSessionsForUsers } from './sessionRevocation.js';

const logger = getLogger('accountRecoveryService');

export const RECOVERY_CODE_TTL_MS = 10 * 60 * 1000;
export const MAX_RECOVERY_CODE_ATTEMPTS = 5;

/**
 * Wrong codes an account may spend on one channel in {@link RECOVERY_FAILURE_WINDOW_MS},
 * across every start. Kept in the database so restarting the flow, or reaching another
 * instance, does not refill it. Per channel, so spending one does not stop the other.
 */
export const RECOVERY_FAILURE_BUDGET = 10;
export const RECOVERY_FAILURE_WINDOW_MS = 24 * 60 * 60 * 1000;

// Not a lockout failure type, so these never lock the account out of signing in.
export function recoveryFailureType(channel: RecoveryChannel) {
  return `account_recovery_${channel}_failed`;
}

function generateRecoveryCode(channel: RecoveryChannel) {
  return channel === 'email'
    ? generateRandomEmailOTP()
    : String(randomInt(10_000_000, 100_000_000));
}

async function spentRecoveryFailures(userId: string, channel: RecoveryChannel) {
  return AuthFailure.count({
    where: {
      userId,
      type: recoveryFailureType(channel),
      occurredAt: { [Op.gte]: new Date(Date.now() - RECOVERY_FAILURE_WINDOW_MS) },
    },
  });
}

/** Whether the channel's budget is spent. An unreadable count is treated as spent. */
export async function isRecoveryChannelLocked(userId: string, channel: RecoveryChannel) {
  try {
    return (await spentRecoveryFailures(userId, channel)) >= RECOVERY_FAILURE_BUDGET;
  } catch (error) {
    logger.error(`Could not read the recovery failure count, treating it as spent: ${error}`);
    return true;
  }
}

async function releaseRecoveryGuess(claimId: string) {
  try {
    await AuthFailure.destroy({ where: { id: claimId } });
  } catch (error) {
    logger.error(`Could not release a recovery guess: ${error}`);
  }
}

/**
 * Spends one guess from the budget before the code is compared. The row is written
 * first and the window counted after, so concurrent guesses on any instance each see
 * the others and no more than the budget get through. Returns null, having spent
 * nothing, when the budget is gone or cannot be checked.
 */
async function claimRecoveryGuess(userId: string, channel: RecoveryChannel) {
  let claimId: string;

  try {
    claimId = (
      await AuthFailure.create({
        userId,
        type: recoveryFailureType(channel),
        occurredAt: new Date(),
      })
    ).id;
  } catch (error) {
    logger.error(`Could not record a recovery guess, refusing it: ${error}`);
    return null;
  }

  try {
    if ((await spentRecoveryFailures(userId, channel)) <= RECOVERY_FAILURE_BUDGET) {
      return claimId;
    }
  } catch (error) {
    logger.error(`Could not read the recovery failure count, refusing the guess: ${error}`);
  }

  await releaseRecoveryGuess(claimId);
  return null;
}

export type RecoveryState = 'pending' | 'ready' | 'cancelled' | 'completed';

export interface RecoveryStatus {
  state: RecoveryState;
  requestedAt: Date;
  completesAt: Date;
}

export function recoveryStatus(request: AccountRecoveryRequest, now = new Date()): RecoveryStatus {
  const completesAt = request.completesAt as Date;
  const stored = request.state as Exclude<StoredRecoveryState, 'awaiting_code' | 'void'>;

  return {
    state: stored === 'pending' && now >= completesAt ? 'ready' : stored,
    requestedAt: request.requestedAt as Date,
    completesAt,
  };
}

function hashCancelToken(token: string) {
  return hashSha256(`account-recovery-cancel:${token}`);
}

/**
 * Issues a code for `attemptId`. When the user already has an open request on this
 * channel, the code goes on that request, so verifying it resumes the request on the new
 * attempt with its clock unchanged. Otherwise it starts a new one. Ephemeral tokens live
 * for minutes and the delay is hours, so coming back means a new attempt, and the same
 * channel is how the requester proves it is them again.
 *
 * Nothing earlier is cancelled here. A stranger who knows the address can call this, and
 * only a verified code may cancel the owner's request.
 *
 * Returns null, issuing nothing, while the channel's failure budget is spent.
 */
export async function startRecovery(userId: string, channel: RecoveryChannel, attemptId: string) {
  if (await isRecoveryChannelLocked(userId, channel)) {
    return null;
  }

  const code = generateRecoveryCode(channel);
  const codeFields = {
    codeAttemptId: attemptId,
    codeHash: hashOtpToken(code),
    codeExpiresAt: new Date(Date.now() + RECOVERY_CODE_TTL_MS),
    failedAttempts: 0,
  };

  await AccountRecoveryRequest.update(
    { state: 'void', codeHash: null, codeAttemptId: null },
    { where: { userId, codeAttemptId: attemptId, state: 'awaiting_code' } },
  );

  const open = await AccountRecoveryRequest.findOne({
    where: { userId, channel, state: 'pending' },
    order: [['requestedAt', 'DESC']],
  });

  if (open) {
    await open.update(codeFields);
  } else {
    await AccountRecoveryRequest.create({ userId, channel, state: 'awaiting_code', ...codeFields });
  }

  return code;
}

export type VerifyRecoveryResult =
  | { outcome: 'invalid' }
  | { outcome: 'locked' }
  | { outcome: 'opened'; request: AccountRecoveryRequest; cancelToken: string }
  | { outcome: 'resumed'; request: AccountRecoveryRequest };

function clearCode(request: AccountRecoveryRequest) {
  return {
    codeHash: null,
    codeAttemptId: null,
    codeExpiresAt: null,
    // A resumed request survives a spent or exhausted code; a new one does not.
    ...(request.state === 'awaiting_code' ? { state: 'void' as const } : {}),
  };
}

/**
 * Checks the code issued to this attempt. Each try is claimed with a conditional update
 * before the code is compared, so parallel requests cannot spend more than
 * {@link MAX_RECOVERY_CODE_ATTEMPTS} between them, or more than the account's
 * {@link RECOVERY_FAILURE_BUDGET} on the channel.
 */
export async function verifyRecovery(
  userId: string,
  attemptId: string,
  code: string,
  delaySeconds: number,
): Promise<VerifyRecoveryResult> {
  const request = await AccountRecoveryRequest.findOne({
    where: {
      userId,
      codeAttemptId: attemptId,
      state: { [Op.in]: ['awaiting_code', 'pending'] },
      codeHash: { [Op.ne]: null },
    },
    order: [['createdAt', 'DESC']],
  });

  if (!request?.codeHash || !request.codeExpiresAt) {
    return { outcome: 'invalid' };
  }

  const tries = request.failedAttempts ?? 0;

  if (request.codeExpiresAt.getTime() <= Date.now() || tries >= MAX_RECOVERY_CODE_ATTEMPTS) {
    await request.update(clearCode(request));
    return { outcome: 'invalid' };
  }

  const guess = await claimRecoveryGuess(userId, request.channel);

  if (!guess) {
    return { outcome: 'locked' };
  }

  const [claimed] = await AccountRecoveryRequest.update(
    { failedAttempts: tries + 1 },
    { where: { id: request.id, failedAttempts: tries } },
  );

  if (claimed !== 1) {
    await releaseRecoveryGuess(guess);
    return { outcome: 'invalid' };
  }

  // Email codes are letters, compared case-insensitively like the login OTP.
  if (!otpHashMatches(request.codeHash, code.toUpperCase())) {
    if (tries + 1 >= MAX_RECOVERY_CODE_ATTEMPTS) {
      await request.update(clearCode(request));
    }
    return { outcome: 'invalid' };
  }

  await releaseRecoveryGuess(guess);

  if (request.state === 'pending') {
    await request.update({ ...clearCode(request), attemptId, failedAttempts: 0 });
    return { outcome: 'resumed', request };
  }

  const cancelToken = randomBytes(32).toString('base64url');
  const requestedAt = new Date();
  const [opened] = await AccountRecoveryRequest.update(
    {
      ...clearCode(request),
      state: 'pending',
      attemptId,
      failedAttempts: 0,
      cancelTokenHash: hashCancelToken(cancelToken),
      requestedAt,
      completesAt: new Date(requestedAt.getTime() + delaySeconds * 1000),
    },
    { where: { id: request.id, state: 'awaiting_code' } },
  );

  if (opened !== 1) {
    return { outcome: 'invalid' };
  }

  await request.reload();

  return { outcome: 'opened', request, cancelToken };
}

/**
 * Cancels the account's other open requests once `request` has been announced. Not done
 * when it opens: a request the owner was never told about must not cancel theirs.
 */
export async function supersedeOtherRecoveries(request: AccountRecoveryRequest) {
  const [cancelled] = await AccountRecoveryRequest.update(
    { state: 'cancelled', cancelledAt: new Date(), codeHash: null, codeAttemptId: null },
    { where: { userId: request.userId, id: { [Op.ne]: request.id }, state: 'pending' } },
  );

  return cancelled;
}

/**
 * Voids a request nobody could be told about. The delay only protects the owner if they
 * learn of it, so a request that reached no verified address must not run.
 */
export async function voidUnannouncedRecovery(request: AccountRecoveryRequest) {
  await AccountRecoveryRequest.update(
    { state: 'void', cancelTokenHash: null, codeHash: null, codeAttemptId: null },
    { where: { id: request.id, state: 'pending' } },
  );
}

/** The request this attempt opened or resumed, if any. */
export async function findRecoveryForAttempt(userId: string, attemptId: string) {
  return AccountRecoveryRequest.findOne({
    where: {
      userId,
      attemptId,
      state: { [Op.in]: ['pending', 'cancelled', 'completed'] },
    },
    order: [['requestedAt', 'DESC']],
  });
}

export type CompleteRecoveryResult =
  | { outcome: 'not_found' }
  | { outcome: 'not_ready'; request: AccountRecoveryRequest }
  | { outcome: 'completed'; request: AccountRecoveryRequest; revokedSessions: number };

/**
 * Completes a ready request and signs out every session on the account. The state
 * change is conditional, so only one caller can complete a request.
 */
export async function completeRecovery(
  userId: string,
  attemptId: string,
): Promise<CompleteRecoveryResult> {
  const request = await findRecoveryForAttempt(userId, attemptId);

  if (!request || request.state !== 'pending') {
    return { outcome: 'not_found' };
  }

  const now = new Date();

  if (recoveryStatus(request, now).state !== 'ready') {
    return { outcome: 'not_ready', request };
  }

  const [completed] = await AccountRecoveryRequest.update(
    { state: 'completed', completedAt: now },
    { where: { id: request.id, state: 'pending', completesAt: { [Op.lte]: now } } },
  );

  if (completed !== 1) {
    return { outcome: 'not_found' };
  }

  const revokedSessions = await revokeAllSessionsForUsers(userId, 'account_recovery');

  await request.reload();

  return { outcome: 'completed', request, revokedSessions };
}

/**
 * Cancels the open request a notice's token belongs to. The token is 32 random bytes,
 * so looking it up by its hash is not a timing oracle on the token itself.
 */
export async function cancelRecoveryByToken(cancelToken: string) {
  const request = await AccountRecoveryRequest.findOne({
    where: { cancelTokenHash: hashCancelToken(cancelToken), state: 'pending' },
  });

  if (!request) {
    return null;
  }

  const [cancelled] = await AccountRecoveryRequest.update(
    { state: 'cancelled', cancelledAt: new Date(), codeHash: null, codeAttemptId: null },
    { where: { id: request.id, state: 'pending' } },
  );

  return cancelled === 1 ? request : null;
}

/** The account's open requests, oldest first, for the owner to review from a session. */
export async function listOpenRecoveries(userId: string) {
  return AccountRecoveryRequest.findAll({
    where: { userId, state: 'pending' },
    order: [['requestedAt', 'ASC']],
  });
}

/**
 * Cancels one of the user's open requests from a signed-in session, without the token.
 * Scoped to the user, so an id belonging to another account matches nothing.
 */
export async function cancelRecoveryForUser(userId: string, requestId: string) {
  const [cancelled] = await AccountRecoveryRequest.update(
    { state: 'cancelled', cancelledAt: new Date(), codeHash: null, codeAttemptId: null },
    { where: { id: requestId, userId, state: 'pending' } },
  );

  return cancelled === 1;
}

/**
 * Whether self-service recovery can be used. Off in phishing-resistant-only mode as well
 * as when disabled: it proves an email address or phone number, which a deployment that
 * only trusts passkeys has decided is not enough. Recovery codes are unaffected.
 */
export function isAccountRecoveryAvailable(config: {
  account_recovery?: { enabled?: boolean } | null;
  phishing_resistant_only?: boolean;
}) {
  return config.account_recovery?.enabled === true && config.phishing_resistant_only !== true;
}
