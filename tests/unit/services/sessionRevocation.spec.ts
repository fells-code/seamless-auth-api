import { beforeEach, describe, expect, it } from 'vitest';

import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import {
  isRevokedByCutoff,
  revokeAllSessionsForUsers,
} from '../../../src/services/sessionRevocation.js';

describe('revokeAllSessionsForUsers', () => {
  beforeEach(() => {
    (Session.update as any).mockResolvedValue([3]);
  });

  it('writes the cutoff, then revokes every live session in one update', async () => {
    const revoked = await revokeAllSessionsForUsers('user-1', 'user_logout_all');

    expect(revoked).toBe(3);
    expect(User.update).toHaveBeenCalledWith(
      { sessionsRevokedBefore: expect.any(Date) },
      { where: { id: 'user-1' } },
    );
    expect(Session.update).toHaveBeenCalledWith(
      { revokedAt: expect.any(Date), revokedReason: 'user_logout_all' },
      { where: { userId: 'user-1', revokedAt: null } },
    );

    const [{ sessionsRevokedBefore }] = (User.update as any).mock.calls[0];
    const [{ revokedAt }] = (Session.update as any).mock.calls[0];
    expect(revokedAt).toBe(sessionsRevokedBefore);
    expect((User.update as any).mock.invocationCallOrder[0]).toBeLessThan(
      (Session.update as any).mock.invocationCallOrder[0],
    );
  });

  it('runs both writes inside the caller transaction', async () => {
    const transaction = {} as any;

    await revokeAllSessionsForUsers(['user-1', 'user-2'], 'oauth_provider_retired', transaction);

    expect(User.update).toHaveBeenCalledWith(expect.anything(), {
      where: { id: ['user-1', 'user-2'] },
      transaction,
    });
    expect(Session.update).toHaveBeenCalledWith(expect.anything(), {
      where: { userId: ['user-1', 'user-2'], revokedAt: null },
      transaction,
    });
  });
});

describe('isRevokedByCutoff', () => {
  const cutoff = new Date('2026-10-22T12:00:00Z');

  it('is false when the user has never revoked everything', () => {
    expect(isRevokedByCutoff({ createdAt: new Date(0) }, null)).toBe(false);
  });

  it('is true for a session created at or before the cutoff', () => {
    expect(isRevokedByCutoff({ createdAt: new Date(cutoff.getTime() - 1) }, cutoff)).toBe(true);
    expect(isRevokedByCutoff({ createdAt: cutoff }, cutoff)).toBe(true);
  });

  it('is false for a session created after the cutoff', () => {
    expect(isRevokedByCutoff({ createdAt: new Date(cutoff.getTime() + 1) }, cutoff)).toBe(false);
  });

  it('fails closed for a session with no creation time', () => {
    expect(isRevokedByCutoff({} as any, cutoff)).toBe(true);
  });
});
