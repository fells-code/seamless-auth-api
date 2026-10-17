import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('../../../src/services/authFailureCounter.js', () => ({
  recentFailureTimes: vi.fn(),
}));

vi.mock('../../../src/services/authEventService.js', () => ({
  AuthEventService: {
    log: vi.fn(),
  },
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { recentFailureTimes } from '../../../src/services/authFailureCounter.js';
import {
  getUserLockoutStatus,
  rejectIfUserLocked,
} from '../../../src/services/lockoutPolicyService.js';

const NOW = new Date('2026-10-16T12:00:00.000Z');

/** Failures `secondsAgo` before NOW, newest first, the order the counter returns. */
function failuresAt(...secondsAgo: number[]) {
  return secondsAgo
    .sort((a, b) => a - b)
    .map((seconds) => new Date(NOW.getTime() - seconds * 1000));
}

describe('lockoutPolicyService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (getSystemConfig as any).mockResolvedValue({
      lockout_policy: {
        enabled: true,
        maxFailures: 3,
        windowSeconds: 900,
        lockoutSeconds: 600,
      },
    });
  });

  it('short-circuits as unlocked when the lockout policy is disabled', async () => {
    (getSystemConfig as any).mockResolvedValue({
      lockout_policy: { enabled: false, maxFailures: 3, windowSeconds: 900, lockoutSeconds: 600 },
    });

    await expect(getUserLockoutStatus('user-1')).resolves.toEqual({
      locked: false,
      failureCount: 0,
      retryAfterSeconds: 0,
      countUnavailable: false,
      policy: expect.objectContaining({ enabled: false }),
    });
    expect(recentFailureTimes).not.toHaveBeenCalled();
  });

  it('falls back to the default policy when config lookup fails', async () => {
    (getSystemConfig as any).mockRejectedValue(new Error('config unavailable'));
    (recentFailureTimes as any).mockResolvedValue(failuresAt(1, 2, 3, 4, 5, 6, 7, 8, 9, 10));

    await expect(getUserLockoutStatus('user-1', NOW)).resolves.toEqual(
      expect.objectContaining({
        locked: true,
        failureCount: 10,
        policy: expect.objectContaining({ enabled: true, maxFailures: 10 }),
      }),
    );
  });

  it('does nothing when the account is not locked', async () => {
    (recentFailureTimes as any).mockResolvedValue([]);

    const req = { ip: '127.0.0.1', headers: {} } as any;
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() } as any;

    await expect(rejectIfUserLocked({ userId: 'user-1', req, res })).resolves.toBe(false);
    expect(res.status).not.toHaveBeenCalled();
    expect(AuthEventService.log).not.toHaveBeenCalled();
  });

  it('reports unlocked when failures are below the configured threshold', async () => {
    (recentFailureTimes as any).mockResolvedValue(failuresAt(10, 20));

    await expect(getUserLockoutStatus('user-1', NOW)).resolves.toEqual(
      expect.objectContaining({
        locked: false,
        failureCount: 2,
      }),
    );
  });

  it('reports locked when failures meet the configured threshold', async () => {
    (recentFailureTimes as any).mockResolvedValue(failuresAt(0, 30, 60));

    await expect(getUserLockoutStatus('user-1', NOW)).resolves.toEqual(
      expect.objectContaining({
        locked: true,
        failureCount: 3,
        retryAfterSeconds: 600,
      }),
    );
  });

  it('counts the lock from the failure that crossed the threshold', async () => {
    (recentFailureTimes as any).mockResolvedValue(failuresAt(200, 230, 260));

    await expect(getUserLockoutStatus('user-1', NOW)).resolves.toEqual(
      expect.objectContaining({ locked: true, retryAfterSeconds: 400 }),
    );
  });

  // lockoutSeconds used to be ignored: the account unlocked as soon as the failures
  // aged out of the window, whatever lockoutSeconds said.
  it('keeps the account locked for lockoutSeconds even after the window has passed', async () => {
    (getSystemConfig as any).mockResolvedValue({
      lockout_policy: { enabled: true, maxFailures: 3, windowSeconds: 60, lockoutSeconds: 3600 },
    });
    (recentFailureTimes as any).mockResolvedValue(failuresAt(1200, 1210, 1220));

    await expect(getUserLockoutStatus('user-1', NOW)).resolves.toEqual(
      expect.objectContaining({ locked: true, failureCount: 0, retryAfterSeconds: 2400 }),
    );
  });

  it('unlocks once lockoutSeconds has passed, even if the window is longer', async () => {
    (getSystemConfig as any).mockResolvedValue({
      lockout_policy: { enabled: true, maxFailures: 3, windowSeconds: 3600, lockoutSeconds: 60 },
    });
    (recentFailureTimes as any).mockResolvedValue(failuresAt(120, 130, 140));

    await expect(getUserLockoutStatus('user-1', NOW)).resolves.toEqual(
      expect.objectContaining({ locked: false, failureCount: 3, retryAfterSeconds: 0 }),
    );
  });

  it('does not lock when the failures are spread wider than one window', async () => {
    (recentFailureTimes as any).mockResolvedValue(failuresAt(0, 500, 1000));

    await expect(getUserLockoutStatus('user-1', NOW)).resolves.toEqual(
      expect.objectContaining({ locked: false }),
    );
  });

  it('asks the counter for no more failures than the threshold', async () => {
    (recentFailureTimes as any).mockResolvedValue([]);

    await getUserLockoutStatus('user-1', NOW);

    expect(recentFailureTimes).toHaveBeenCalledWith('user-1', 3);
  });

  it('returns a lockout response and audit event when active', async () => {
    (recentFailureTimes as any).mockResolvedValue([new Date(), new Date(), new Date()]);

    const req = {
      ip: '127.0.0.1',
      headers: { 'user-agent': 'vitest' },
    } as any;
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    } as any;

    await expect(rejectIfUserLocked({ userId: 'user-1', req, res })).resolves.toBe(true);

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'login_suspicious',
      }),
    );
    expect(res.status).toHaveBeenCalledWith(423);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'account_locked',
        retryAfterSeconds: 600,
      }),
    );
  });

  // The advisory: the count used to coalesce a failed query to zero, which read
  // as not locked, so brute force protection came off exactly when the database
  // was unhealthy. An unknown count now means locked.
  it('treats the account as locked when the counter cannot be read', async () => {
    (recentFailureTimes as any).mockRejectedValue(new Error('connection pool exhausted'));

    const status = await getUserLockoutStatus('user-1');

    expect(status.locked).toBe(true);
    expect(status.countUnavailable).toBe(true);
  });

  it('refuses the request when the counter cannot be read', async () => {
    (recentFailureTimes as any).mockRejectedValue(new Error('table is locked'));
    const res: any = { status: vi.fn().mockReturnThis(), json: vi.fn().mockReturnThis() };

    await expect(rejectIfUserLocked({ userId: 'user-1', req: {} as never, res })).resolves.toBe(
      true,
    );
    expect(res.status).toHaveBeenCalledWith(423);
  });
});
