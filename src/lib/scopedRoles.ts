/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

export const ROLE_NAME_PATTERN = /^(?!.*[_/\\\s])(?=.{1,80}$)[A-Za-z0-9-]+(?::[A-Za-z0-9-]+)*$/;

function normalizeRole(value: string) {
  return value.trim();
}

function samePrefix(left: string[], right: string[]) {
  return left.length === right.length && left.every((part, index) => part === right[index]);
}

export function roleGrantsAccess(grantedRole: string, requiredRole: string) {
  const granted = normalizeRole(grantedRole);
  const required = normalizeRole(requiredRole);

  if (!granted || !required) {
    return false;
  }

  if (granted === required) {
    return true;
  }

  if (granted.endsWith(':*')) {
    const prefix = granted.slice(0, -2);
    return required === prefix || required.startsWith(`${prefix}:`);
  }

  if (!required.includes(':')) {
    return false;
  }

  if (!granted.includes(':')) {
    return required.startsWith(`${granted}:`);
  }

  const grantedParts = granted.split(':');
  const requiredParts = required.split(':');
  const grantedAction = grantedParts.at(-1);
  const requiredAction = requiredParts.at(-1);

  return (
    grantedAction === 'write' &&
    requiredAction === 'read' &&
    samePrefix(grantedParts.slice(0, -1), requiredParts.slice(0, -1))
  );
}

export function hasScopedRole(grantedRoles: unknown, requiredRoles: string | string[]) {
  if (!Array.isArray(grantedRoles)) {
    return false;
  }

  const required = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  const granted = grantedRoles.filter((role): role is string => typeof role === 'string');

  return required.some((requiredRole) =>
    granted.some((grantedRole) => roleGrantsAccess(grantedRole, requiredRole)),
  );
}
