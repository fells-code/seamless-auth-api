/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import type { LockoutPolicy } from '../schemas/systemConfig.schema.js';
import getLogger from '../utils/logger.js';
import { AuthEventService } from './authEventService.js';
import { countRecentFailures } from './authFailureCounter.js';

const logger = getLogger('lockoutPolicy');

const DEFAULT_LOCKOUT_POLICY: LockoutPolicy = {
  enabled: true,
  maxFailures: 10,
  windowSeconds: 15 * 60,
  lockoutSeconds: 15 * 60,
};

async function getLockoutPolicy(): Promise<LockoutPolicy> {
  let configuredPolicy: LockoutPolicy | undefined;

  try {
    const config = await getSystemConfig();
    configuredPolicy = config.lockout_policy;
  } catch {
    configuredPolicy = undefined;
  }

  return {
    ...DEFAULT_LOCKOUT_POLICY,
    ...(configuredPolicy ?? {}),
  };
}

export async function getUserLockoutStatus(userId: string, now = new Date()) {
  const policy = await getLockoutPolicy();

  if (!policy.enabled) {
    return {
      locked: false,
      failureCount: 0,
      retryAfterSeconds: 0,
      policy,
      countUnavailable: false,
    };
  }

  const windowStart = new Date(now.getTime() - policy.windowSeconds * 1000);

  let failureCount: number;

  try {
    failureCount = await countRecentFailures(userId, windowStart);
  } catch (error) {
    // Fail closed. This used to coalesce a failed query to zero, which read as
    // not locked, so the brute force protection came off exactly when the
    // database was unhealthy. Refusing an authentication we cannot vouch for is
    // the lesser harm, and the caller sees the same 423 a locked account gets.
    logger.error(`Could not read the lockout counter, treating the account as locked: ${error}`);

    return {
      locked: true,
      failureCount: policy.maxFailures,
      retryAfterSeconds: policy.lockoutSeconds,
      policy,
      countUnavailable: true,
    };
  }

  return {
    locked: failureCount >= policy.maxFailures,
    failureCount,
    retryAfterSeconds: policy.lockoutSeconds,
    policy,
    countUnavailable: false,
  };
}

export async function rejectIfUserLocked(params: { userId: string; req: Request; res: Response }) {
  const status = await getUserLockoutStatus(params.userId);

  if (!status.locked) {
    return false;
  }

  await AuthEventService.log({
    userId: params.userId,
    type: 'login_suspicious',
    req: params.req,
    metadata: {
      reason: 'Account lockout policy active',
      failureCount: status.failureCount,
      retryAfterSeconds: status.retryAfterSeconds,
    },
  });

  params.res.status(423).json({
    error: 'account_locked',
    message: 'Too many failed authentication attempts. Try again later.',
    retryAfterSeconds: status.retryAfterSeconds,
  });

  return true;
}
