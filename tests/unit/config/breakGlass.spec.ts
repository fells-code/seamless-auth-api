import { describe, expect, it } from 'vitest';

import {
  breakGlassEmails,
  isBreakGlassAdmin,
  isBreakGlassConfigured,
} from '../../../src/config/breakGlass.js';

const env = { BREAK_GLASS_EMAILS: ' Root@Example.com, ,second@example.com ,' };

describe('breakGlassEmails', () => {
  it('trims, lower-cases and drops empty entries', () => {
    expect([...breakGlassEmails(env)]).toEqual(['root@example.com', 'second@example.com']);
  });

  it('is empty when the variable is unset', () => {
    expect(breakGlassEmails({}).size).toBe(0);
    expect(isBreakGlassConfigured({})).toBe(false);
    expect(isBreakGlassConfigured(env)).toBe(true);
  });
});

describe('isBreakGlassAdmin', () => {
  it.each([['admin:write'], ['admin'], ['admin:*']])(
    'exempts a listed account holding %s',
    (role) => {
      expect(isBreakGlassAdmin({ email: 'ROOT@example.com ', roles: ['user', role] }, env)).toBe(
        true,
      );
    },
  );

  it('gives a listed account without admin:write no exemption', () => {
    expect(isBreakGlassAdmin({ email: 'root@example.com', roles: ['admin:read'] }, env)).toBe(
      false,
    );
    expect(isBreakGlassAdmin({ email: 'root@example.com', roles: null }, env)).toBe(false);
  });

  it('gives an unlisted admin no exemption', () => {
    expect(isBreakGlassAdmin({ email: 'other@example.com', roles: ['admin'] }, env)).toBe(false);
  });

  it('gives a revoked account, or no account, no exemption', () => {
    expect(
      isBreakGlassAdmin({ email: 'root@example.com', roles: ['admin'], revoked: true }, env),
    ).toBe(false);
    expect(isBreakGlassAdmin(null, env)).toBe(false);
    expect(isBreakGlassAdmin({ email: null, roles: ['admin'] }, env)).toBe(false);
  });

  it('reads process.env by default', () => {
    expect(isBreakGlassAdmin({ email: 'root@example.com', roles: ['admin'] })).toBe(
      breakGlassEmails().has('root@example.com'),
    );
  });
});
