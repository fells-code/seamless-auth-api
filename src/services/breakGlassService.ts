/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { Op } from 'sequelize';

import { breakGlassEmails, type BreakGlassEnv, isBreakGlassAdmin } from '../config/breakGlass.js';
import { getSystemConfig } from '../config/getSystemConfig.js';
import { hasScopedRole } from '../lib/scopedRoles.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { AuthEventService } from './authEventService.js';
import {
  getLoginPolicy,
  isLoginMethodEnabled,
  isPasskeyRequiredForUser,
  type LoginPolicy,
} from './loginPolicyService.js';
import { sendNoticeEmail } from './messagingService.js';
import { getRecoveryCodeStatus } from './recoveryCodeService.js';
import { getTotpStatus } from './totpService.js';

const logger = getLogger('breakGlass');

// Every role string that can satisfy admin:read, used to narrow the query before the
// exact check. hasScopedRole stays the authority on what each one grants.
const ADMIN_GRANTS = ['admin', 'admin:*', 'admin:write', 'admin:read'];

/** The factors a break-glass account may sign in with. Everything else is refused. */
export type BreakGlassFactor = 'passkey' | 'totp' | 'recovery_code';

/** A policy a break-glass sign-in or enrollment went around, as named in the audit trail. */
export type BreakGlassWaiver =
  | 'login_methods'
  | 'phishing_resistant_only'
  | 'passkey_required'
  | 'recovery_codes_disabled'
  | 'authenticator_policy';

export type BreakGlassNoticeSummary = { sent: number; failed: number };

/**
 * Counts, never addresses: the log is not where the list of accounts that bypass policy
 * should be readable from.
 */
export async function warnOnBreakGlassMisconfiguration(env: BreakGlassEnv = process.env) {
  const listed = [...breakGlassEmails(env)];

  if (listed.length === 0) return;

  const users = await User.findAll({
    attributes: ['email', 'roles', 'revoked'],
    where: { email: { [Op.in]: listed } },
  });
  const admins = users.filter((user) => isBreakGlassAdmin(user, env)).length;
  const notAdmins = listed.length - admins;

  if (notAdmins > 0) {
    logger.warn(
      `${notAdmins} of ${listed.length} BREAK_GLASS_EMAILS entries are not admin accounts ` +
        'and get no break-glass exemption',
    );
    return;
  }

  logger.info(`Break-glass configured for ${listed.length} admin account(s)`);
}

/**
 * What the policy in force would have refused this sign-in for, had the account not
 * been break-glass. Empty means the sign-in was ordinary and is not announced.
 */
export async function breakGlassWaivers(
  factor: BreakGlassFactor,
  userId: string,
  policy?: LoginPolicy,
): Promise<BreakGlassWaiver[]> {
  if (factor === 'recovery_code') {
    const { recovery_codes } = await getSystemConfig();
    return recovery_codes?.enabled === false ? ['recovery_codes_disabled'] : [];
  }

  const resolved = policy ?? (await getLoginPolicy());

  if (factor === 'passkey') {
    return isLoginMethodEnabled(resolved, 'passkey') ? [] : ['login_methods'];
  }

  if (resolved.phishingResistantOnly) return ['phishing_resistant_only'];

  return (await isPasskeyRequiredForUser(userId, resolved)) ? ['passkey_required'] : [];
}

/**
 * Whether a break-glass account with no passkey can still continue from `/login`, with
 * TOTP or a recovery code. Neither is a login method, so `/login` lists nothing for them.
 * TOTP is subject to lockout like any code; recovery codes are not.
 */
export async function hasBreakGlassCodeFactor(userId: string, locked: boolean) {
  if ((await getRecoveryCodeStatus(userId)).remaining > 0) return true;

  return !locked && (await getTotpStatus(userId)).enabled;
}

async function adminRecipients() {
  const admins = await User.findAll({
    attributes: ['email', 'roles'],
    where: {
      revoked: false,
      emailVerified: true,
      roles: { [Op.overlap]: ADMIN_GRANTS },
    },
  });

  return admins
    .filter((admin) => admin.email && hasScopedRole(admin.roles ?? [], 'admin:read'))
    .map((admin) => admin.email);
}

async function noticeEveryAdmin(
  subjectEmail: string,
  factor: BreakGlassFactor,
  waived: BreakGlassWaiver[],
): Promise<BreakGlassNoticeSummary> {
  const summary = { sent: 0, failed: 0 };

  try {
    const appName = (await getSystemConfig())?.app_name ?? 'Seamless Auth';
    const subject = `Break-glass sign-in on ${appName}`;
    const text =
      `The break-glass admin account ${subjectEmail} signed in to ${appName} with ` +
      `${factor.replace('_', ' ')}, bypassing sign-in policy (${waived.join(', ')}) at ` +
      `${new Date().toISOString()}. If this was not a planned recovery, review the audit ` +
      'trail, revoke the sessions and rotate the break-glass credentials.';

    for (const to of await adminRecipients()) {
      try {
        await sendNoticeEmail(to, subject, text);
        summary.sent += 1;
      } catch {
        summary.failed += 1;
      }
    }
  } catch (error) {
    // The sign-in has already been answered, and the audit event below still records it.
    logger.error(`Failed to send break-glass notices: ${error}`);
  }

  return summary;
}

/**
 * Called after the session is issued, so a notice that cannot be sent never costs an
 * administrator the recovery they are in the middle of. The audit model has no severity
 * column, so the event carries `severity: 'high'` in its metadata.
 */
export async function recordBreakGlassSignIn(params: {
  req: Request;
  user: { id: string; email: string };
  factor: BreakGlassFactor;
  waived: BreakGlassWaiver[];
}) {
  const { req, user, factor, waived } = params;

  if (waived.length === 0) return;

  const notices = await noticeEveryAdmin(user.email, factor, waived);

  await AuthEventService.log({
    userId: user.id,
    type: 'break_glass_sign_in',
    req,
    metadata: { severity: 'high', factor, waived, notices },
  });
}

/**
 * Email OTP, SMS OTP, magic links and OAuth prove control of an address or an outside
 * identity, which is exactly what someone taking over a break-glass account would have.
 * The account signs in with a passkey, TOTP or a recovery code, whatever else is enabled.
 */
export async function rejectWeakFactorForBreakGlass(
  user: Parameters<typeof isBreakGlassAdmin>[0] & { id?: string },
  method: string,
  req: Request,
  res: Response,
): Promise<boolean> {
  if (!isBreakGlassAdmin(user)) return false;

  await AuthEventService.log({
    userId: user?.id ?? null,
    type: 'login_failed',
    req,
    metadata: { reason: 'Break-glass account requires a strong factor', method },
  });

  res.status(403).json({ error: 'login_method_disabled' });
  return true;
}
