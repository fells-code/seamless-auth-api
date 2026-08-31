/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Op } from 'sequelize';

import { AuthFailure } from '../models/authFailures.js';
import getLogger from '../utils/logger.js';
import { recordAuditWriteFailure } from './auditHealth.js';

const logger = getLogger('authFailureCounter');

/**
 * The event types that count towards account lockout.
 *
 * Kept here rather than in the lockout policy because this is now what decides
 * whether an attempt is recorded at all, and the policy only reads the total.
 */
export const LOCKOUT_FAILURE_TYPES = [
  'login_failed',
  'webauthn_login_failed',
  'verify_otp_failed',
  'totp_failed',
  'magic_link_failed',
];

export function isLockoutFailureType(type: string): boolean {
  return LOCKOUT_FAILURE_TYPES.includes(type);
}

/**
 * Records a failed attempt against the lockout counter.
 *
 * A no-op for anything that is not a lockout failure, and for an attempt that
 * could not be tied to a user, since lockout is per account.
 *
 * Does not throw. A counter that cannot be written means an attacker gets one
 * extra attempt, which is worse than nothing but far better than failing the
 * request; and unlike before, it is reported rather than swallowed, so the
 * instance shows degraded instead of quietly under-counting.
 */
export async function recordAuthFailure(params: {
  userId: string | null | undefined;
  type: string;
  occurredAt?: Date;
}): Promise<boolean> {
  const { userId, type } = params;

  if (!userId || !isLockoutFailureType(type)) {
    return false;
  }

  try {
    await AuthFailure.create({
      userId,
      type,
      occurredAt: params.occurredAt ?? new Date(),
    });

    return true;
  } catch (error) {
    recordAuditWriteFailure(error);
    logger.error(`Failed to record an authentication failure for lockout: ${error}`);

    return false;
  }
}

/**
 * How many failures a user has accumulated inside the window.
 *
 * Throws rather than returning a number it does not have. The caller decides
 * what an unknown count means, and for lockout that has to be "assume locked":
 * the previous implementation coalesced a failed query to zero, which read as
 * not locked and removed the control exactly when the database was unhealthy.
 */
export async function countRecentFailures(userId: string, since: Date): Promise<number> {
  const count = await AuthFailure.count({
    where: {
      userId,
      occurredAt: { [Op.gte]: since },
    },
  });

  return Number(count);
}
