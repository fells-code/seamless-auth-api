/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type {
  AdminEnrollmentQuery,
  EnrollmentInviteRequest,
  EnrollmentInviteResponse,
  EnrollmentInviteResult,
  EnrollmentStatus,
} from '@seamless-auth/types';
import { ENROLLMENT_INVITE_MAX_USERS } from '@seamless-auth/types';
import { QueryTypes } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { allowedRedirect } from '../lib/redirectAllowlist.js';
import { Credential } from '../models/credentials.js';
import { getSequelize } from '../models/index.js';
import { User } from '../models/users.js';
import { DeliveryError } from './deliveryError.js';
import { getLoginPolicy } from './loginPolicyService.js';
import { sendEnrollmentInviteEmail } from './messagingService.js';

const RESEND_AFTER_MS = 24 * 60 * 60 * 1000;
const DEFAULT_SIGN_IN_PATH = '/login';

interface EnrollmentRow {
  id: string;
  email: string;
  imported: boolean;
  credentialCount: number;
  lastLogin: Date | null;
  enrollmentInvitedAt: Date | null;
}

interface BaseFilters {
  organizationId?: string;
  imported?: boolean;
  search?: string;
  userIds?: string[];
}

export class EnrollmentInviteError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'EnrollmentInviteError';
  }
}

/**
 * The `nextStep` a sign-in response carries when the tenant asks users without a passkey
 * to enroll one. Spread into the session response's extra fields.
 */
export async function passkeyEnrollmentPrompt(userId: string): Promise<Record<string, string>> {
  const { prompt_passkey_enrollment } = await getSystemConfig();

  if (!prompt_passkey_enrollment) return {};

  const credentials = await Credential.count({ where: { userId } });

  return credentials === 0 ? { nextStep: 'enroll_passkey' } : {};
}

export function enrollmentStatus(credentialCount: number): EnrollmentStatus {
  if (credentialCount === 0) return 'none';
  if (credentialCount === 1) return 'one';
  return 'two_or_more';
}

function escapeLike(value: string) {
  return value.replace(/[\\%_]/g, (match) => `\\${match}`);
}

/**
 * Every active user matching the filters, with their WebAuthn credential count. Revoked
 * users are left out: they cannot sign in, so they are not part of anyone's rollout.
 */
function baseQuery(filters: BaseFilters) {
  const replacements: Record<string, unknown> = {};
  const where = ['u.revoked = false'];
  let join = '';

  if (filters.organizationId) {
    join =
      'JOIN organization_memberships m ON m.user_id = u.id AND m.organization_id = :organizationId';
    replacements.organizationId = filters.organizationId;
  }

  if (filters.imported !== undefined) {
    where.push(
      `${filters.imported ? '' : 'NOT '}EXISTS (SELECT 1 FROM user_external_ids x WHERE x.user_id = u.id)`,
    );
  }

  if (filters.search) {
    where.push("u.email ILIKE :search ESCAPE '\\'");
    replacements.search = `%${escapeLike(filters.search)}%`;
  }

  if (filters.userIds) {
    where.push('u.id IN (:userIds)');
    replacements.userIds = filters.userIds;
  }

  const sql = `
    SELECT
      u.id,
      u.email,
      u.last_login AS "lastLogin",
      u.enrollment_invited_at AS "enrollmentInvitedAt",
      EXISTS (SELECT 1 FROM user_external_ids x WHERE x.user_id = u.id) AS imported,
      (SELECT COUNT(*)::int FROM credentials c WHERE c."userId" = u.id) AS "credentialCount"
    FROM users u
    ${join}
    WHERE ${where.join(' AND ')}
  `;

  return { sql, replacements };
}

const STATUS_CONDITION: Record<EnrollmentStatus, string> = {
  none: '"credentialCount" = 0',
  one: '"credentialCount" = 1',
  two_or_more: '"credentialCount" >= 2',
};

function serializeRow(row: EnrollmentRow) {
  return {
    id: row.id,
    email: row.email,
    imported: row.imported,
    credentialCount: row.credentialCount,
    status: enrollmentStatus(row.credentialCount),
    lastLogin: row.lastLogin,
    enrollmentInvitedAt: row.enrollmentInvitedAt,
  };
}

export async function listEnrollment(query: AdminEnrollmentQuery) {
  const sequelize = getSequelize();
  const { sql, replacements } = baseQuery(query);
  const statusCondition = query.status ? STATUS_CONDITION[query.status] : 'TRUE';

  const [counts] = await sequelize.query<{
    total: number;
    none: number;
    one: number;
    twoOrMore: number;
    filtered: number;
  }>(
    `WITH base AS (${sql})
     SELECT
       COUNT(*)::int AS total,
       (COUNT(*) FILTER (WHERE "credentialCount" = 0))::int AS none,
       (COUNT(*) FILTER (WHERE "credentialCount" = 1))::int AS one,
       (COUNT(*) FILTER (WHERE "credentialCount" >= 2))::int AS "twoOrMore",
       (COUNT(*) FILTER (WHERE ${statusCondition}))::int AS filtered
     FROM base`,
    { replacements, type: QueryTypes.SELECT },
  );

  const rows = await sequelize.query<EnrollmentRow>(
    `WITH base AS (${sql})
     SELECT * FROM base
     WHERE ${statusCondition}
     ORDER BY email, id
     LIMIT :limit OFFSET :offset`,
    {
      replacements: { ...replacements, limit: query.limit, offset: query.offset },
      type: QueryTypes.SELECT,
    },
  );

  return {
    summary: {
      total: counts?.total ?? 0,
      none: counts?.none ?? 0,
      one: counts?.one ?? 0,
      twoOrMore: counts?.twoOrMore ?? 0,
    },
    users: rows.map(serializeRow),
    total: counts?.filtered ?? 0,
  };
}

/**
 * Where the invite sends the user. The link only opens the sign-in page, but it is still
 * a destination in an email the tenant's users will trust, so a requested one has to be
 * on one of the tenant's own origins.
 */
async function resolveSignInUrl(requested?: string) {
  const config = await getSystemConfig();

  if (requested) {
    if (!allowedRedirect(requested, [], config.origins)) {
      throw new EnrollmentInviteError(400, 'signInUrl is not on an allowed origin');
    }
    return requested;
  }

  const base = config.frontend_url ?? config.origins[0];

  if (!base) {
    throw new EnrollmentInviteError(400, 'No sign-in URL is configured; pass signInUrl');
  }

  return new URL(DEFAULT_SIGN_IN_PATH, base).toString();
}

/**
 * A user without a passkey needs another way in to enroll one. Inviting them to a
 * tenant that only allows passkeys would send them to a sign-in page that cannot sign
 * them in.
 */
async function assertNonPasskeySignInAvailable() {
  const [policy, config] = await Promise.all([getLoginPolicy(), getSystemConfig()]);
  const methods = policy.loginMethods.filter((method) => method !== 'passkey');
  const oauthUsable = (config.oauth_providers ?? []).some((provider) => provider.enabled);
  const usable = methods.filter((method) => method !== 'oauth' || oauthUsable);

  if (usable.length === 0) {
    throw new EnrollmentInviteError(
      409,
      'No sign-in method other than passkey is enabled, so a user without one could not sign in to enroll',
    );
  }
}

async function selectTargets(request: EnrollmentInviteRequest, maxCredentials: number) {
  const sequelize = getSequelize();
  const resendBefore = new Date(Date.now() - RESEND_AFTER_MS);

  if (request.userIds) {
    const { sql, replacements } = baseQuery({ userIds: request.userIds });
    const rows = await sequelize.query<EnrollmentRow>(sql, {
      replacements,
      type: QueryTypes.SELECT,
    });
    const byId = new Map(rows.map((row) => [row.id, row]));

    return {
      candidates: request.userIds.map((userId) => ({ userId, row: byId.get(userId) })),
      remaining: undefined,
    };
  }

  const { sql, replacements } = baseQuery({ organizationId: request.organizationId });
  const eligible = `"credentialCount" <= :maxCredentials
    AND ("enrollmentInvitedAt" IS NULL OR "enrollmentInvitedAt" < :resendBefore)`;
  const scoped = { ...replacements, maxCredentials, resendBefore };

  const [{ count }] = await sequelize.query<{ count: number }>(
    `WITH base AS (${sql}) SELECT COUNT(*)::int AS count FROM base WHERE ${eligible}`,
    { replacements: scoped, type: QueryTypes.SELECT },
  );
  const rows = await sequelize.query<EnrollmentRow>(
    `WITH base AS (${sql}) SELECT * FROM base WHERE ${eligible} ORDER BY email, id LIMIT :limit`,
    {
      replacements: { ...scoped, limit: ENROLLMENT_INVITE_MAX_USERS },
      type: QueryTypes.SELECT,
    },
  );

  return {
    candidates: rows.map((row) => ({ userId: row.id, row })),
    remaining: count,
  };
}

/**
 * Sends each target a notice to sign in and add a passkey. The notice carries no
 * credential: the user signs in however the tenant allows, and `nextStep` (with
 * `prompt_passkey_enrollment` on) takes them into enrollment from there.
 */
export async function inviteToEnroll(
  request: EnrollmentInviteRequest,
  { external }: { external: boolean },
): Promise<EnrollmentInviteResponse & { invitedUserIds: string[] }> {
  await assertNonPasskeySignInAvailable();

  const signInUrl = await resolveSignInUrl(request.signInUrl);
  const maxCredentials = request.status === 'one' ? 1 : 0;
  const resendBefore = Date.now() - RESEND_AFTER_MS;
  const { candidates, remaining } = await selectTargets(request, maxCredentials);

  const results: EnrollmentInviteResult[] = [];
  const invitedUserIds: string[] = [];

  for (const { userId, row } of candidates) {
    if (!row) {
      results.push({ userId, status: 'skipped', reason: 'not_found' });
      continue;
    }

    if (row.credentialCount > maxCredentials) {
      results.push({ userId, status: 'skipped', reason: 'already_enrolled' });
      continue;
    }

    if (row.enrollmentInvitedAt && new Date(row.enrollmentInvitedAt).getTime() >= resendBefore) {
      results.push({ userId, status: 'skipped', reason: 'recently_invited' });
      continue;
    }

    if (external) {
      results.push({
        userId,
        status: 'sent',
        delivery: { kind: 'enrollment_invite_email', to: row.email, signInUrl },
      });
      invitedUserIds.push(userId);
      continue;
    }

    try {
      await sendEnrollmentInviteEmail(row.email, signInUrl);
      results.push({ userId, status: 'sent' });
      invitedUserIds.push(userId);
    } catch (error) {
      if (!(error instanceof DeliveryError)) throw error;
      results.push({ userId, status: 'skipped', reason: 'delivery_failed' });
    }
  }

  if (invitedUserIds.length > 0) {
    await User.update({ enrollmentInvitedAt: new Date() }, { where: { id: invitedUserIds } });
  }

  const sent = invitedUserIds.length;

  return {
    sent,
    skipped: results.length - sent,
    ...(remaining === undefined ? {} : { remaining: Math.max(remaining - sent, 0) }),
    results,
    invitedUserIds,
  };
}
