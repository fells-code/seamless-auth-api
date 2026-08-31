import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthFailure } from '../../../src/models/authFailures.js';
import { getAuditHealth, resetAuditHealthForTests } from '../../../src/services/auditHealth.js';
import {
  countRecentFailures,
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

describe('countRecentFailures', () => {
  it('counts a user inside the window', async () => {
    (AuthFailure.count as any).mockResolvedValue(4);
    const since = new Date('2026-08-31T00:00:00.000Z');

    await expect(countRecentFailures('user-1', since)).resolves.toBe(4);
    expect(AuthFailure.count).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ userId: 'user-1' }) }),
    );
  });

  // The caller decides what an unknown count means. Returning a number here would
  // be inventing one, which is exactly how the old `|| 0` removed the control.
  it('propagates a failed query instead of coalescing it to zero', async () => {
    (AuthFailure.count as any).mockRejectedValue(new Error('connection pool exhausted'));

    await expect(countRecentFailures('user-1', new Date())).rejects.toThrow(
      'connection pool exhausted',
    );
  });
});

describe('isLockoutFailureType', () => {
  it('recognises the types that count', () => {
    expect(isLockoutFailureType('totp_failed')).toBe(true);
    expect(isLockoutFailureType('magic_link_failed')).toBe(true);
    expect(isLockoutFailureType('login_success')).toBe(false);
  });
});
