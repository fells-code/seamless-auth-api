/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * Managed instances are provisioned with an `OWNER_EMAIL` (the tenant owner,
 * optionally a comma separated list). A user who signs up with an owner email is
 * granted the admin role on account creation, so a freshly provisioned instance
 * has a working `/console` admin as soon as the owner signs up.
 *
 * The grant is safe because both signup paths establish control of the email
 * before the account is created (email OTP verification, or a verified OAuth
 * profile), so only someone who actually receives mail at the owner address can
 * claim it. When `OWNER_EMAIL` is unset the helpers are no-ops, so non-managed
 * deployments are unaffected.
 */

const ADMIN_ROLE = 'admin';

function ownerEmails(): Set<string> {
  return new Set(
    (process.env.OWNER_EMAIL ?? '')
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function isOwnerEmail(email: string | null | undefined): boolean {
  if (!email) {
    return false;
  }
  return ownerEmails().has(email.trim().toLowerCase());
}

/**
 * Returns `baseRoles` with the admin role appended when `email` is a configured
 * owner email and the instance lists admin as an available role. Idempotent, and
 * a no-op when `OWNER_EMAIL` is unset or admin is not an available role.
 */
export function withOwnerAdminRole(
  baseRoles: string[],
  email: string | null | undefined,
  availableRoles: string[],
): string[] {
  if (!isOwnerEmail(email)) {
    return baseRoles;
  }
  if (!availableRoles.includes(ADMIN_ROLE) || baseRoles.includes(ADMIN_ROLE)) {
    return baseRoles;
  }
  return [...baseRoles, ADMIN_ROLE];
}
