/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

/**
 * `OWNER_EMAIL` names the instance owner (optionally a comma separated list). An
 * account created for an owner email gets one admin role at creation, so a new
 * instance has a working `/console` admin as soon as the owner signs up.
 *
 * Email OTP registration creates the account, role included, before the address is
 * verified, but an unverified account cannot sign in, so only someone who receives
 * the code at the owner address can use it. OAuth signup creates it from a verified
 * provider email. When `OWNER_EMAIL` is unset the helpers are no-ops.
 */

/**
 * The owner is granted full admin write, not read-only: they paid for the instance
 * and must be able to run it, including granting admin to teammates. The grant is
 * expressed as `admin:write` so the owner's authority is stated in the scoped
 * vocabulary rather than relying on the broad legacy role. Instances that predate
 * scoped roles and list only `admin` still get `admin`, which is equivalent in
 * power, so the grant never silently becomes a no-op.
 */
const OWNER_ADMIN_ROLES: readonly string[] = ['admin:write', 'admin'];

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
 * Returns `baseRoles` with the owner's admin role appended when `email` is a
 * configured owner email and the instance lists one of the admin roles as
 * available. Idempotent, and a no-op when `OWNER_EMAIL` is unset or no admin role
 * is available.
 */
export function withOwnerAdminRole(
  baseRoles: string[],
  email: string | null | undefined,
  availableRoles: string[],
): string[] {
  if (!isOwnerEmail(email)) {
    return baseRoles;
  }

  if (baseRoles.some((role) => OWNER_ADMIN_ROLES.includes(role))) {
    return baseRoles;
  }

  const grant = OWNER_ADMIN_ROLES.find((role) => availableRoles.includes(role));

  return grant ? [...baseRoles, grant] : baseRoles;
}
