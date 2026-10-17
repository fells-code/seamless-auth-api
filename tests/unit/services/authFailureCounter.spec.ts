import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthFailure } from '../../../src/models/authFailures.js';
import { getAuditHealth, resetAuditHealthForTests } from '../../../src/services/auditHealth.js';
import {
  recentFailureTimes,
  isLockoutFailureType,
  recordAuthFailure,
} from '../../../src/services/authFailureCounter.js';

beforeEach(() => {
  resetAuditHealthForTests();
  (AuthFailure.create as any).mockResolvedValue({});
  (AuthFailure.count as any).mockResolvedValue(0);
});

describe('recordAuthFailure', () => {
  it('records a failure that counts towards lockout', async () => {
    const occurredAt = new Date('2026-08-31T00:00:00.000Z');

    await expect(
      recordAuthFailure({ userId: 'user-1', type: 'login_failed', occurredAt }),
    ).resolves.toBe(true);

    expect(AuthFailure.create).toHaveBeenCalledWith({
      userId: 'user-1',
      type: 'login_failed',
      occurredAt,
    });
  });

  it.each(['login_success', 'registration_failed', 'informational'])(
    'ignores %s, which lockout does not count',
    async (type) => {
      await expect(recordAuthFailure({ userId: 'user-1', type })).resolves.toBe(false);
      expect(AuthFailure.create).not.toHaveBeenCalled();
    },
  );

  // Lockout is per account, so a failure that could not be tied to one has
  // nothing to count against.
  it.each([[null], [undefined], ['']])('ignores an attempt with no user (%s)', async (userId) => {
    await expect(
      recordAuthFailure({ userId: userId as string | null, type: 'login_failed' }),
    ).resolves.toBe(false);
    expect(AuthFailure.create).not.toHaveBeenCalled();
  });

  // An attacker gets one extra attempt, which beats failing the request, but it
  // is reported rather than swallowed the way the audit write used to be.
  it('reports degraded rather than throwing when the counter cannot be written', async () => {
    (AuthFailure.create as any).mockRejectedValue(new Error('disk full'));

    await expect(recordAuthFailure({ userId: 'user-1', type: 'login_failed' })).resolves.toBe(
      false,
    );
    expect(getAuditHealth().degraded).toBe(true);
  });
});

describe('recentFailureTimes', () => {
  it('returns the newest lockout failures for a user, filtered by type', async () => {
    const at = new Date('2026-10-16T12:00:00.000Z');
    (AuthFailure.findAll as any).mockResolvedValue([{ occurredAt: at }]);

    await expect(recentFailureTimes('user-1', 10)).resolves.toEqual([at]);
    expect(AuthFailure.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ userId: 'user-1', type: expect.anything() }),
        order: [['occurredAt', 'DESC']],
        limit: 10,
      }),
    );
  });

  // The caller decides what an unknown history means. Returning a list here would
  // be inventing one, which is exactly how the old `|| 0` removed the control.
  it('propagates a failed query instead of inventing an empty history', async () => {
    (AuthFailure.findAll as any).mockRejectedValue(new Error('connection pool exhausted'));

    await expect(recentFailureTimes('user-1', 10)).rejects.toThrow('connection pool exhausted');
  });
});

describe('isLockoutFailureType', () => {
  it('recognises the types that count', () => {
    expect(isLockoutFailureType('totp_failed')).toBe(true);
    expect(isLockoutFailureType('magic_link_failed')).toBe(true);
    // A failed second factor is a failed authentication attempt too. Left out, TOTP
    // step-up was the one code-checking endpoint whose guesses reached no counter.
    expect(isLockoutFailureType('mfa_otp_failed')).toBe(true);
    expect(isLockoutFailureType('login_success')).toBe(false);
    // An assertion cannot be guessed, so a failed one does not count towards a lock.
    expect(isLockoutFailureType('webauthn_login_failed')).toBe(false);
  });
});
