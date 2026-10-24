/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import type { AttestationType } from '../lib/attestationType.js';
import { Credential } from '../models/credentials.js';
import { getSequelize } from '../models/index.js';
import type {
  PolicyDocument,
  PolicyDryRunReason,
  PolicyDryRunResponse,
  PolicyDryRunUser,
} from '../schemas/policy.schema.js';
import { evaluateAuthenticatorPolicy } from './authenticatorPolicyService.js';
import { SIGN_IN_EVENT_TYPES } from './coverageReport.js';
import {
  isLoginMethodEnabled,
  isPasskeyRequired,
  type LoginPolicy,
  normalizeLoginPolicy,
  resolveAvailableLoginMethods,
} from './loginPolicyService.js';

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The most accounts one dry run evaluates, so its cost stays bounded on a large instance.
 * Past this it evaluates the first accounts by id and records that it was capped.
 */
export const POLICY_DRY_RUN_USER_CAP = 10_000;

/** `otp` is a code verification written before the channel was recorded. */
export type DryRunSignInMethod =
  'passkey' | 'magic_link' | 'email_otp' | 'phone_otp' | 'otp' | 'oauth' | 'totp';

export interface DryRunAccount {
  email: string | null;
  phone: string | null;
  hasPasskey: boolean;
  oauthProviders: string[];
}

interface SignInRow {
  userId: string;
  email: string | null;
  phone: string | null;
  method: DryRunSignInMethod;
  signIns: number;
  hasPasskey: boolean;
  oauthProviders: string[] | null;
}

/**
 * Break-glass accounts are exempt from policy, so a dry run counts them and never lists
 * them. Read from `BREAK_GLASS_EMAILS`, a comma separated list.
 */
export function breakGlassEmails(): Set<string> {
  return new Set(
    (process.env.BREAK_GLASS_EMAILS ?? '')
      .split(',')
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean),
  );
}

/**
 * Why the policy would refuse a sign-in made with `method`, or null if it would not.
 *
 * Mirrors the checks the sign-in endpoints make. Authenticator rules are not among them:
 * the API applies `authenticator_policy` when a passkey is registered, not when it signs
 * in, so tightening it leaves an enrolled passkey working and is not reported here.
 */
export function signInRefusal(
  policy: LoginPolicy,
  method: DryRunSignInMethod,
  hasPasskey: boolean,
): PolicyDryRunReason | null {
  if (method === 'passkey') {
    return isLoginMethodEnabled(policy, 'passkey') ? null : 'method_disabled';
  }

  if (policy.phishingResistantOnly) {
    return 'phishing_resistant_required';
  }

  if (method !== 'totp') {
    const enabled =
      method === 'otp'
        ? isLoginMethodEnabled(policy, 'email_otp') || isLoginMethodEnabled(policy, 'phone_otp')
        : isLoginMethodEnabled(policy, method);

    if (!enabled) {
      return 'method_disabled';
    }
  }

  // OAuth completes without the ephemeral token the passkey requirement is checked on.
  if (method !== 'oauth' && isPasskeyRequired(policy, hasPasskey)) {
    return 'fallback_disabled';
  }

  return null;
}

/** Whether any factor the account holds would still sign it in under the policy. */
export function hasUsableFactor(
  policy: LoginPolicy,
  account: DryRunAccount,
  enabledOAuthProviders: ReadonlySet<string>,
) {
  const methods = resolveAvailableLoginMethods({
    policy,
    user: { email: account.email, phone: account.phone },
    hasPasskeyCredential: account.hasPasskey,
  });

  if (methods.length > 0) return true;

  return (
    isLoginMethodEnabled(policy, 'oauth') &&
    account.oauthProviders.some((provider) => enabledOAuthProviders.has(provider))
  );
}

/**
 * Completed sign-ins in the window per account and method, folded by attempt the way the
 * coverage report folds them. Registration attempts are left out: the code a new account
 * verifies its address with is allowed under every policy, so it says nothing about one.
 *
 * Driven by the `(type, created_at)` index on `auth_events`, and capped at one more
 * account than is evaluated so the caller can tell the cap was reached.
 */
async function signInsInWindow(from: Date, to: Date, cap: number) {
  return getSequelize().query<SignInRow>(
    `
    WITH sign_ins AS (
      SELECT e.user_id,
             COALESCE(e.attempt_id::text, e.id::text) AS attempt,
             CASE
               WHEN e.type = :passkeyType THEN 'passkey'
               WHEN e.type = :otpType AND e.metadata->>'channel' = 'email' THEN 'email_otp'
               WHEN e.type = :otpType AND e.metadata->>'channel' = 'sms' THEN 'phone_otp'
               WHEN e.type = :otpType THEN 'otp'
               WHEN e.type = :magicLinkType THEN 'magic_link'
               WHEN e.type = :totpType THEN 'totp'
               WHEN e.type = :oauthType THEN 'oauth'
             END AS method
      FROM auth_events e
      WHERE e.type IN (:types)
        AND e.created_at >= :from
        AND e.created_at < :to
        AND e.user_id IS NOT NULL
        AND (e.type <> :totpType OR e.metadata->>'flow' = 'login')
        AND NOT (
          e.attempt_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM auth_events r
            WHERE r.attempt_id = e.attempt_id AND r.type = 'user_created'
          )
        )
    ),
    scoped AS (
      SELECT u.id, u.email, u.phone
      FROM users u
      WHERE u.revoked = false
        AND u.id IN (SELECT user_id FROM sign_ins)
      ORDER BY u.id
      LIMIT :cap
    )
    SELECT s.id AS "userId",
           s.email,
           s.phone,
           i.method,
           COUNT(DISTINCT i.attempt)::int AS "signIns",
           EXISTS (SELECT 1 FROM credentials c WHERE c."userId" = s.id) AS "hasPasskey",
           ARRAY(
             SELECT DISTINCT o.provider_id FROM oauth_identities o WHERE o.user_id = s.id
           ) AS "oauthProviders"
    FROM scoped s
    JOIN sign_ins i ON i.user_id = s.id
    GROUP BY s.id, s.email, s.phone, i.method
    ORDER BY s.id, i.method
    `,
    {
      replacements: {
        from,
        to,
        cap,
        types: Object.values(SIGN_IN_EVENT_TYPES),
        passkeyType: SIGN_IN_EVENT_TYPES.passkey,
        otpType: SIGN_IN_EVENT_TYPES.otp,
        magicLinkType: SIGN_IN_EVENT_TYPES.magic_link,
        totpType: SIGN_IN_EVENT_TYPES.totp,
        oauthType: SIGN_IN_EVENT_TYPES.oauth,
      },
      type: QueryTypes.SELECT,
    },
  );
}

async function countBreakGlassAccounts(emails: ReadonlySet<string>) {
  if (emails.size === 0) return 0;

  const [row] = await getSequelize().query<{ count: number }>(
    `SELECT COUNT(*)::int AS count FROM users WHERE revoked = false AND lower(email) IN (:emails)`,
    { replacements: { emails: [...emails] }, type: QueryTypes.SELECT },
  );

  return row?.count ?? 0;
}

const ATTESTATION_TYPES: ReadonlySet<string> = new Set(['none', 'self', 'basic']);

/**
 * Users holding a passkey the candidate authenticator policy would not admit if it were
 * registered today. That passkey keeps signing in, since the policy applies at
 * registration, so this is reported as a reason without counting a refused sign-in: it is
 * what the user could not enroll again.
 */
async function authenticatorRefusals(
  userIds: string[],
  policy: PolicyDocument['authenticator_policy'],
) {
  const refusals = new Map<string, Set<PolicyDryRunReason>>();
  if (userIds.length === 0) return refusals;

  const credentials = await Credential.findAll({
    where: { userId: userIds },
    attributes: ['userId', 'aaguid', 'deviceType', 'attestationType'],
  });

  for (const credential of credentials) {
    const attestationType: AttestationType = ATTESTATION_TYPES.has(credential.attestationType ?? '')
      ? (credential.attestationType as AttestationType)
      : 'none';
    const verdict = evaluateAuthenticatorPolicy({
      policy,
      aaguid: credential.aaguid,
      deviceType: credential.deviceType,
      attestationType,
    });

    if (verdict.allowed) continue;

    const reasons = refusals.get(credential.userId) ?? new Set<PolicyDryRunReason>();
    reasons.add(
      verdict.reason === 'synced_passkey_not_allowed'
        ? 'synced_passkey_blocked'
        : 'authenticator_not_allowed',
    );
    refusals.set(credential.userId, reasons);
  }

  return refusals;
}

function byAccount(rows: SignInRow[]) {
  const accounts = new Map<string, { account: DryRunAccount; email: string; rows: SignInRow[] }>();

  for (const row of rows) {
    const entry = accounts.get(row.userId) ?? {
      account: {
        email: row.email,
        phone: row.phone,
        hasPasskey: Boolean(row.hasPasskey),
        oauthProviders: row.oauthProviders ?? [],
      },
      email: row.email ?? '',
      rows: [],
    };

    entry.rows.push(row);
    accounts.set(row.userId, entry);
  }

  return accounts;
}

export async function runPolicyDryRun(params: {
  policy: PolicyDocument;
  days: number;
  now?: Date;
  cap?: number;
}): Promise<PolicyDryRunResponse & { capped: boolean }> {
  const to = params.now ?? new Date();
  const from = new Date(to.getTime() - params.days * DAY_MS);
  const cap = params.cap ?? POLICY_DRY_RUN_USER_CAP;
  const policy = normalizeLoginPolicy(params.policy as unknown as Record<string, unknown>);
  const breakGlass = breakGlassEmails();

  const [rows, breakGlassAccounts, config] = await Promise.all([
    signInsInWindow(from, to, cap + 1),
    countBreakGlassAccounts(breakGlass),
    getSystemConfig(),
  ]);

  const enabledOAuthProviders = new Set(
    config.oauth_providers.filter((provider) => provider.enabled).map((provider) => provider.id),
  );
  const accounts = [...byAccount(rows)];
  const capped = accounts.length > cap;

  let signInsEvaluated = 0;
  let usersEvaluated = 0;
  const wouldFail: PolicyDryRunUser[] = [];
  const evaluated = accounts
    .slice(0, cap)
    .filter(([, { email }]) => !breakGlass.has(email.toLowerCase()));
  const passkeyRefusals = await authenticatorRefusals(
    evaluated.filter(([, { account }]) => account.hasPasskey).map(([userId]) => userId),
    params.policy.authenticator_policy,
  );

  for (const [userId, { account, email, rows: signIns }] of evaluated) {
    usersEvaluated += 1;

    const reasons = new Set<PolicyDryRunReason>(passkeyRefusals.get(userId));
    let refused = 0;

    for (const row of signIns) {
      signInsEvaluated += row.signIns;

      const reason = signInRefusal(policy, row.method, account.hasPasskey);

      if (reason) {
        reasons.add(reason);
        refused += row.signIns;
      }
    }

    if (reasons.size > 0) {
      wouldFail.push({
        userId,
        email,
        signIns: refused,
        reasons: [...reasons].sort(),
        lockedOut: !hasUsableFactor(policy, account, enabledOAuthProviders),
      });
    }
  }

  // Accounts that would have no way back in first, since they are the ones to act on.
  wouldFail.sort(
    (a, b) => Number(b.lockedOut) - Number(a.lockedOut) || a.email.localeCompare(b.email),
  );

  return {
    window: { from: from.toISOString(), to: to.toISOString() },
    signInsEvaluated,
    usersEvaluated,
    wouldFail,
    usersLockedOut: wouldFail.filter((user) => user.lockedOut).length,
    breakGlassAccounts,
    capped,
  };
}
