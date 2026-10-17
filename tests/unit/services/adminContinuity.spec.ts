import { beforeEach, describe, expect, it, vi } from 'vitest';

import { User } from '../../../src/models/users.js';
import { wouldLeaveNoAdmin } from '../../../src/services/adminContinuity.js';

describe('wouldLeaveNoAdmin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('ignores users who cannot administer anything', async () => {
    await expect(wouldLeaveNoAdmin({ id: 'u1', roles: ['user'] }, null)).resolves.toBe(false);
    expect(User.findAll).not.toHaveBeenCalled();
  });

  it('allows a role change that keeps admin write', async () => {
    await expect(
      wouldLeaveNoAdmin({ id: 'u1', roles: ['admin'] }, ['admin:write', 'user']),
    ).resolves.toBe(false);
    expect(User.findAll).not.toHaveBeenCalled();
  });

  it('refuses removing the only admin', async () => {
    (User.findAll as any).mockResolvedValue([]);

    await expect(wouldLeaveNoAdmin({ id: 'u1', roles: ['admin:write'] }, null)).resolves.toBe(true);
  });

  // The query only narrows by role name; the exact check decides what each role grants.
  it('does not count another user who can only read', async () => {
    (User.findAll as any).mockResolvedValue([{ id: 'u2', roles: ['admin:read'] }]);

    await expect(wouldLeaveNoAdmin({ id: 'u1', roles: ['admin'] }, ['user'])).resolves.toBe(true);
  });

  it('allows it when another active user keeps admin write', async () => {
    (User.findAll as any).mockResolvedValue([{ id: 'u2', roles: ['admin:*'] }]);

    await expect(wouldLeaveNoAdmin({ id: 'u1', roles: ['admin'] }, null)).resolves.toBe(false);
    expect(User.findAll).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ revoked: false }) }),
    );
  });
});
