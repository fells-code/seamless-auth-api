/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { AuthEvent } from '../models/authEvents.js';
import type { LockoutPolicy } from '../schemas/systemConfig.schema.js';
import { AuthEventService } from './authEventService.js';

const DEFAULT_LOCKOUT_POLICY: LockoutPolicy = {
  enabled: true,
  maxFailures: 10,
  windowSeconds: 15 * 60,
  lockoutSeconds: 15 * 60,
};

const LOCKOUT_FAILURE_TYPES = [
  'login_failed',
  'webauthn_login_failed',
  'verify_otp_failed',
  'totp_failed',
  'magic_link_failed',
];

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
    };
  }

  const windowStart = new Date(now.getTime() - policy.windowSeconds * 1000);
  const failureCount =
    Number(
      await AuthEvent.count({
        where: {
          user_id: userId,
          type: { [Op.in]: LOCKOUT_FAILURE_TYPES },
          created_at: { [Op.gte]: windowStart },
        },
      }),
    ) || 0;

  return {
    locked: failureCount >= policy.maxFailures,
    failureCount,
    retryAfterSeconds: policy.lockoutSeconds,
    policy,
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
