import { describe, expect, it } from 'vitest';

import { hasScopedRole, roleGrantsAccess } from '../../../src/lib/scopedRoles.js';

describe('scoped roles', () => {
  it('matches exact roles', () => {
    expect(roleGrantsAccess('admin', 'admin')).toBe(true);
    expect(roleGrantsAccess('admin:read', 'admin:read')).toBe(true);
  });

  it('lets a broad legacy role grant scoped access', () => {
    expect(roleGrantsAccess('admin', 'admin:read')).toBe(true);
    expect(roleGrantsAccess('admin', 'admin:write')).toBe(true);
  });

  it('lets write satisfy read for the same role path', () => {
    expect(roleGrantsAccess('admin:write', 'admin:read')).toBe(true);
    expect(roleGrantsAccess('admin:users:write', 'admin:users:read')).toBe(true);
  });

  it('does not let read satisfy write or a broad role check', () => {
    expect(roleGrantsAccess('admin:read', 'admin:write')).toBe(false);
    expect(roleGrantsAccess('admin:read', 'admin')).toBe(false);
  });

  it('checks any granted role against any required role', () => {
    expect(hasScopedRole(['user', 'admin:read'], ['admin:write', 'admin:read'])).toBe(true);
    expect(hasScopedRole(['user'], ['admin:write', 'admin:read'])).toBe(false);
  });

  it('rejects empty or whitespace-only roles', () => {
    expect(roleGrantsAccess('', 'admin')).toBe(false);
    expect(roleGrantsAccess('admin', '   ')).toBe(false);
  });

  it('lets a wildcard role grant the base role and any scoped child', () => {
    expect(roleGrantsAccess('admin:*', 'admin')).toBe(true);
    expect(roleGrantsAccess('admin:*', 'admin:read')).toBe(true);
    expect(roleGrantsAccess('admin:*', 'billing')).toBe(false);
  });

  it('returns false when granted roles are not an array', () => {
    expect(hasScopedRole(undefined, 'admin')).toBe(false);
    expect(hasScopedRole('admin', 'admin')).toBe(false);
  });

  it('coerces a single required role and ignores non-string granted entries', () => {
    expect(hasScopedRole(['admin', 42], 'admin:read')).toBe(true);
  });
});
