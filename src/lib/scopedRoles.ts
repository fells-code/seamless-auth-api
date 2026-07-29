/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

export { hasScopedRole, ROLE_NAME_PATTERN, roleGrantsAccess } from '@seamless-auth/types';

function normalizeRole(value: string) {
  return value.trim();
}

/**
 * Returns the assigned roles that are not in the instance's `available_roles`.
 *
 * The match is exact rather than scope-aware: listing `admin:write` does not make
 * `admin:write:users` assignable. Enforcement (`roleGrantsAccess`) never matches an
 * off-list role, so accepting one would store a grant that silently does nothing.
 *
 * Stays local because this is assignment policy, not matching: the shared package owns
 * the rules for whether a held role satisfies a required one, not which roles an
 * instance chooses to offer.
 */
export function unavailableRoles(assignedRoles: string[], availableRoles: string[]): string[] {
  const available = new Set(availableRoles.map(normalizeRole));

  return assignedRoles.filter((role) => !available.has(normalizeRole(role)));
}
