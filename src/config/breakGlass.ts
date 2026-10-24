/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { hasScopedRole } from '../lib/scopedRoles.js';

export type BreakGlassEnv = Record<string, string | undefined>;

/**
 * `BREAK_GLASS_EMAILS` names admin accounts that sign-in policy cannot lock out, so a
 * bad policy change (phishing-resistant only with no enrolled keys, say) always leaves
 * a way back. Set at deploy time rather than in `system_config`, because anything the
 * API can edit is something a bad edit can remove.
 */
export function breakGlassEmails(env: BreakGlassEnv = process.env): Set<string> {
  return new Set(
    (env.BREAK_GLASS_EMAILS ?? '')
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function isBreakGlassConfigured(env: BreakGlassEnv = process.env): boolean {
  return breakGlassEmails(env).size > 0;
}

export type BreakGlassCandidate = {
  email?: string | null;
  roles?: string[] | null;
  revoked?: boolean | null;
};

/**
 * Being listed is not enough. The account must also hold a role that satisfies
 * `admin:write`, so the variable cannot hand a policy exemption to an ordinary user,
 * and removing the role is enough to take the exemption away.
 */
export function isBreakGlassAdmin(
  user: BreakGlassCandidate | null | undefined,
  env: BreakGlassEnv = process.env,
): boolean {
  if (!user?.email || user.revoked) return false;
  if (!breakGlassEmails(env).has(user.email.trim().toLowerCase())) return false;

  return hasScopedRole(user.roles ?? [], 'admin:write');
}
