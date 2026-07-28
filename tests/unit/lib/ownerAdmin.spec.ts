import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { isOwnerEmail, withOwnerAdminRole } from '../../../src/lib/ownerAdmin.js';

const AVAILABLE = ['user', 'admin', 'betaUser', 'team'];
const DEFAULTS = ['user', 'betaUser'];

describe('ownerAdmin', () => {
  const original = process.env.OWNER_EMAIL;

  beforeEach(() => {
    delete process.env.OWNER_EMAIL;
  });

  afterEach(() => {
    if (original === undefined) {
      delete process.env.OWNER_EMAIL;
    } else {
      process.env.OWNER_EMAIL = original;
    }
  });

  describe('isOwnerEmail', () => {
    it('is false when OWNER_EMAIL is unset', () => {
      expect(isOwnerEmail('owner@example.com')).toBe(false);
    });

    it('matches case-insensitively and trims whitespace', () => {
      process.env.OWNER_EMAIL = 'Owner@Example.com';
      expect(isOwnerEmail('  owner@example.com  ')).toBe(true);
      expect(isOwnerEmail('someone@else.com')).toBe(false);
    });

    it('matches any entry in a comma separated list', () => {
      process.env.OWNER_EMAIL = 'a@x.com, b@y.com';
      expect(isOwnerEmail('a@x.com')).toBe(true);
      expect(isOwnerEmail('b@y.com')).toBe(true);
      expect(isOwnerEmail('c@z.com')).toBe(false);
    });

    it('is false for null/undefined/empty', () => {
      process.env.OWNER_EMAIL = 'owner@example.com';
      expect(isOwnerEmail(null)).toBe(false);
      expect(isOwnerEmail(undefined)).toBe(false);
      expect(isOwnerEmail('')).toBe(false);
    });
  });

  describe('withOwnerAdminRole', () => {
    it('returns base roles unchanged when OWNER_EMAIL is unset', () => {
      expect(withOwnerAdminRole(DEFAULTS, 'owner@example.com', AVAILABLE)).toEqual(DEFAULTS);
    });

    it('grants admin:write to a matching owner email', () => {
      process.env.OWNER_EMAIL = 'owner@example.com';
      expect(
        withOwnerAdminRole(DEFAULTS, 'owner@example.com', [...AVAILABLE, 'admin:write']),
      ).toEqual([...DEFAULTS, 'admin:write']);
    });

    it('falls back to admin when the instance predates scoped roles', () => {
      process.env.OWNER_EMAIL = 'owner@example.com';
      expect(withOwnerAdminRole(DEFAULTS, 'owner@example.com', AVAILABLE)).toEqual([
        ...DEFAULTS,
        'admin',
      ]);
    });

    it('does not grant admin to a non-owner email', () => {
      process.env.OWNER_EMAIL = 'owner@example.com';
      expect(withOwnerAdminRole(DEFAULTS, 'user@example.com', AVAILABLE)).toEqual(DEFAULTS);
    });

    it('does not grant admin when admin is not an available role', () => {
      process.env.OWNER_EMAIL = 'owner@example.com';
      expect(withOwnerAdminRole(DEFAULTS, 'owner@example.com', ['user', 'betaUser'])).toEqual(
        DEFAULTS,
      );
    });

    it('is idempotent when an admin role is already present', () => {
      process.env.OWNER_EMAIL = 'owner@example.com';

      for (const base of [
        ['user', 'admin'],
        ['user', 'admin:write'],
      ]) {
        expect(
          withOwnerAdminRole(base, 'owner@example.com', [...AVAILABLE, 'admin:write']),
        ).toEqual(base);
      }
    });

    it('does not mutate the input array', () => {
      process.env.OWNER_EMAIL = 'owner@example.com';
      const base = [...DEFAULTS];
      withOwnerAdminRole(base, 'owner@example.com', AVAILABLE);
      expect(base).toEqual(DEFAULTS);
    });
  });
});
