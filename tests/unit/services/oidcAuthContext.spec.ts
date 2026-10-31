import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/sessions', () => ({
  Session: { findByPk: vi.fn() },
}));

import { Session } from '../../../src/models/sessions';
import {
  deriveAcrAmr,
  getOidcAuthContext,
  isUuid,
  resolveCurrentSession,
} from '../../../src/services/oidcAuthContext';
import { validateSessionRecord } from '../../../src/services/sessionService';

const at = '2026-10-30T12:00:00.000Z';
const S1 = '11111111-1111-4111-8111-111111111111';
const S2 = '22222222-2222-4222-8222-222222222222';

function row(overrides: Record<string, unknown> = {}) {
  return {
    id: S1,
    userId: 'user-1',
    recovery: false,
    authMethods: [],
    authTime: null,
    createdAt: new Date(at),
    revokedAt: null,
    replacedBySessionId: null,
    ...overrides,
  };
}

describe('deriveAcrAmr', () => {
  it('gives phrh and hwk for a device-bound verified passkey', () => {
    expect(
      deriveAcrAmr([{ method: 'passkey', at, deviceBound: true, userVerified: true }]),
    ).toEqual({ acr: 'phrh', amr: ['hwk', 'user', 'mfa'] });
  });

  it('gives phr and swk for a synced verified passkey', () => {
    expect(
      deriveAcrAmr([{ method: 'passkey', at, deviceBound: false, userVerified: true }]),
    ).toEqual({ acr: 'phr', amr: ['swk', 'user', 'mfa'] });
  });

  it('keeps phrh once earned in the session', () => {
    expect(
      deriveAcrAmr([
        { method: 'passkey', at, deviceBound: true, userVerified: true },
        { method: 'passkey', at, deviceBound: false, userVerified: true },
      ]).acr,
    ).toBe('phrh');
  });

  it('gives no acr for a passkey without user verification', () => {
    expect(deriveAcrAmr([{ method: 'passkey', at }])).toEqual({ acr: null, amr: ['swk'] });
  });

  it('maps codes and links to otp, SMS to sms and otp', () => {
    expect(deriveAcrAmr([{ method: 'email_otp', at }]).amr).toEqual(['otp']);
    expect(deriveAcrAmr([{ method: 'magic_link', at }]).amr).toEqual(['otp']);
    expect(deriveAcrAmr([{ method: 'totp', at }]).amr).toEqual(['otp']);
    expect(deriveAcrAmr([{ method: 'phone_otp', at }]).amr).toEqual(['otp', 'sms']);
  });

  it('earns nothing for oauth or a recovery code alone', () => {
    expect(deriveAcrAmr([{ method: 'oauth', at }])).toEqual({ acr: null, amr: [] });
    expect(deriveAcrAmr([{ method: 'recovery_code', at }])).toEqual({ acr: null, amr: [] });
  });

  it('adds mfa for two distinct methods', () => {
    expect(
      deriveAcrAmr([
        { method: 'email_otp', at },
        { method: 'totp', at },
      ]).amr,
    ).toEqual(['otp', 'mfa']);
  });
});

describe('isUuid', () => {
  it('accepts a uuid only', () => {
    expect(isUuid(S1)).toBe(true);
    expect(isUuid('session-1')).toBe(false);
  });
});

describe('resolveCurrentSession', () => {
  beforeEach(() => {
    vi.mocked(validateSessionRecord).mockImplementation(async (id: string) => ({ id }) as never);
  });

  it('refuses a malformed id without a query', async () => {
    expect(await resolveCurrentSession('nope')).toBeNull();
    expect(Session.findByPk).not.toHaveBeenCalled();
  });

  it('returns null for an unknown session', async () => {
    vi.mocked(Session.findByPk).mockResolvedValue(null);
    expect(await resolveCurrentSession(S1)).toBeNull();
  });

  it('follows rotations to the current row and validates it', async () => {
    vi.mocked(Session.findByPk).mockImplementation((async (id: string) =>
      id === S1 ? row({ replacedBySessionId: S2 }) : row({ id: S2 })) as never);

    expect(await resolveCurrentSession(S1)).toEqual({ id: S2 });
    expect(validateSessionRecord).toHaveBeenCalledWith(S2);
  });

  it('returns null when a link points at nothing', async () => {
    vi.mocked(Session.findByPk).mockImplementation((async (id: string) =>
      id === S1 ? row({ replacedBySessionId: S2 }) : null) as never);

    expect(await resolveCurrentSession(S1)).toBeNull();
  });

  it('stops at a revoked row', async () => {
    vi.mocked(Session.findByPk).mockResolvedValue(
      row({ replacedBySessionId: S2, revokedAt: new Date() }) as never,
    );

    await resolveCurrentSession(S1);
    expect(validateSessionRecord).toHaveBeenCalledWith(S1);
  });
});

describe('getOidcAuthContext', () => {
  it('returns null for a malformed or unknown id', async () => {
    expect(await getOidcAuthContext('nope')).toBeNull();
    vi.mocked(Session.findByPk).mockResolvedValue(null);
    expect(await getOidcAuthContext(S1)).toBeNull();
  });

  it('reports the current row of the chain, where step-up records', async () => {
    const authTime = new Date('2026-10-30T12:30:00.000Z');
    const steppedUp = [
      { method: 'email_otp', at },
      { method: 'passkey', at: authTime.toISOString(), deviceBound: true, userVerified: true },
    ];
    vi.mocked(Session.findByPk).mockResolvedValue(
      row({ authMethods: [{ method: 'email_otp', at }], authTime: new Date(at) }) as never,
    );
    vi.mocked(validateSessionRecord).mockResolvedValue(
      row({ id: S2, recovery: true, authMethods: steppedUp, authTime }) as never,
    );

    expect(await getOidcAuthContext(S1)).toEqual({
      sessionId: S1,
      userId: 'user-1',
      active: true,
      recovery: true,
      authMethods: steppedUp,
      authTime: Math.floor(authTime.getTime() / 1000),
      acr: 'phrh',
      amr: ['hwk', 'user', 'otp', 'mfa'],
    });
  });

  it('falls back to the start of the chain for rows without an auth time', async () => {
    const chainStartedAt = new Date('2026-10-30T11:00:00.000Z');
    vi.mocked(Session.findByPk).mockResolvedValue(row() as never);
    vi.mocked(validateSessionRecord).mockResolvedValue(row({ chainStartedAt }) as never);

    expect((await getOidcAuthContext(S1))?.authTime).toBe(
      Math.floor(chainStartedAt.getTime() / 1000),
    );
  });

  it('falls back to createdAt and reports a dead chain', async () => {
    vi.mocked(Session.findByPk).mockResolvedValue(row({ authMethods: undefined }) as never);
    vi.mocked(validateSessionRecord).mockResolvedValue(null);

    const context = await getOidcAuthContext(S1);

    expect(context).toMatchObject({ active: false, recovery: false, authMethods: [], acr: null });
    expect(context?.authTime).toBe(Math.floor(new Date(at).getTime() / 1000));
  });
});
