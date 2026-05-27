import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: {
    count: vi.fn(),
  },
}));

vi.mock('../../../src/services/authEventService.js', () => ({
  AuthEventService: {
    log: vi.fn(),
  },
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { AuthEvent } from '../../../src/models/authEvents.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  getUserLockoutStatus,
  rejectIfUserLocked,
} from '../../../src/services/lockoutPolicyService.js';

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

  it('reports unlocked when failures are below the configured threshold', async () => {
    (AuthEvent.count as any).mockResolvedValue(2);

    await expect(getUserLockoutStatus('user-1')).resolves.toEqual(
      expect.objectContaining({
        locked: false,
        failureCount: 2,
      }),
    );
  });

  it('reports locked when failures meet the configured threshold', async () => {
    (AuthEvent.count as any).mockResolvedValue(3);

    await expect(getUserLockoutStatus('user-1')).resolves.toEqual(
      expect.objectContaining({
        locked: true,
        failureCount: 3,
        retryAfterSeconds: 600,
      }),
    );
  });

  it('returns a lockout response and audit event when active', async () => {
    (AuthEvent.count as any).mockResolvedValue(3);

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
});
