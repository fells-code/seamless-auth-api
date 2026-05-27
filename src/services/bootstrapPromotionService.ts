/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import crypto from 'crypto';
import { Request } from 'express';
import { literal, Transaction } from 'sequelize';

import { hasScopedRole } from '../lib/scopedRoles.js';
import { BootstrapInvite } from '../models/bootstrapInvites.js';
import { getSequelize } from '../models/index.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { AuthEventService } from './authEventService.js';

type CompletionMethod = 'webauthn_registration' | 'magic_link_fallback' | 'email_otp' | 'phone_otp';

export const BOOTSTRAP_INVITE_TOKEN_HASH_CONTEXT_KEY = 'bootstrapInviteTokenHash';

type PromotionResult =
  | { promoted: true; reason: 'success' }
  | {
      promoted: false;
      reason:
        | 'bootstrap_disabled'
        | 'missing_token'
        | 'invalid_token'
        | 'invite_expired'
        | 'invite_consumed'
        | 'email_mismatch'
        | 'admin_exists'
        | 'already_admin';
    };

const logger = getLogger('bootstrapPromotionService');

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function hashBootstrapToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function createBootstrapInviteTokenHash(token: string): string {
  return hashBootstrapToken(token);
}

export function getBootstrapInviteTokenHash(user: User): string | null {
  const value = user.challengeContext?.[BOOTSTRAP_INVITE_TOKEN_HASH_CONTEXT_KEY];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function isBootstrapEnabled(): boolean {
  return process.env.SEAMLESS_BOOTSTRAP_ENABLED === 'true';
}

function userHasAdminRole(user: User): boolean {
  return hasScopedRole(user.roles, 'admin:write');
}

function addAdminRole(user: User): void {
  const currentRoles = Array.isArray(user.roles) ? user.roles : [];
  if (!currentRoles.includes('admin')) {
    user.roles = [...currentRoles, 'admin'];
  }
}

export async function maybePromoteBootstrapAdmin(params: {
  user: User;
  req: Request;
  completionMethod: CompletionMethod;
  bootstrapInviteTokenHash?: string | null;
}): Promise<PromotionResult> {
  const { user, req, completionMethod } = params;
  logger.debug('checking for promotion');

  async function logSkip(reason: string) {
    logger.info(`Skipped bootstrap for ${reason}`);
    await AuthEventService.log({
      userId: user.id,
      type: 'bootstrap_admin_check_skipped',
      req,
      metadata: { reason, completionMethod },
    });
  }

  if (!isBootstrapEnabled()) {
    logSkip('disabled');
    return { promoted: false, reason: 'bootstrap_disabled' };
  }

  if (userHasAdminRole(user)) {
    logSkip('bootstrap_admin_check_skipped');
    return { promoted: false, reason: 'already_admin' };
  }

  const tokenHash = params.bootstrapInviteTokenHash ?? getBootstrapInviteTokenHash(user);
  if (!tokenHash) {
    logSkip('Missing token');
    return { promoted: false, reason: 'missing_token' };
  }

  const now = new Date();

  const invite = await BootstrapInvite.findOne({
    where: { tokenHash },
  });

  if (!invite) {
    await logSkip('Invalid token');
    return { promoted: false, reason: 'invalid_token' };
  }

  if (invite.consumedAt) {
    await logSkip('Token already used');
    return { promoted: false, reason: 'invite_consumed' };
  }

  if (invite.expiresAt <= now) {
    await logSkip('Invitation expired');
    return { promoted: false, reason: 'invite_expired' };
  }

  if (normalizeEmail(invite.email) !== normalizeEmail(user.email)) {
    await logSkip('Email mismatch');
    return { promoted: false, reason: 'email_mismatch' };
  }

  return getSequelize().transaction(async (transaction: Transaction) => {
    const adminCount = await User.count({
      where: literal(`"roles" && ARRAY['admin','admin:write']::varchar[]`),
      transaction,
    });

    if (adminCount > 0) {
      return { promoted: false, reason: 'admin_exists' } as PromotionResult;
    }

    addAdminRole(user);
    await user.save({ transaction });

    const [updated] = await BootstrapInvite.update(
      { consumedAt: now },
      {
        where: {
          id: invite.id,
          consumedAt: null,
        },
        transaction,
      },
    );

    if (!updated) {
      return { promoted: false, reason: 'invite_consumed' } as PromotionResult;
    }

    await AuthEventService.log({
      userId: user.id,
      type: 'bootstrap_admin_granted',
      req,
      metadata: {
        completionMethod,
        inviteId: invite.id,
        email: user.email,
      },
    });

    logger.info('User promoted to admin');

    return { promoted: true, reason: 'success' } as PromotionResult;
  });
}
