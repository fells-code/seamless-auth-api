import { describe, it, expect, vi, beforeEach } from 'vitest';

import {
  createBootstrapInviteTokenHash,
  maybePromoteBootstrapAdmin,
} from '../../../src/services/bootstrapPromotionService.js';

// ---- mocks ----

vi.mock('../../../src/models/bootstrapInvites.js', () => ({
  BootstrapInvite: {
    findOne: vi.fn(),
    update: vi.fn(),
  },
}));

vi.mock('../../../src/models/users.js', () => ({
  User: {
    count: vi.fn(),
  },
}));

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

vi.mock('../../../src/services/authEventService.js', () => ({
  AuthEventService: {
    log: vi.fn(),
    refreshTokenFailed: vi.fn(),
    requestSuspicious: vi.fn(),
    requestSuspiciousContext: vi.fn(),
  },
}));

// ---- imports AFTER mocks ----

import { BootstrapInvite } from '../../../src/models/bootstrapInvites.js';
import { User } from '../../../src/models/users.js';
import { getSequelize } from '../../../src/models/index.js';
import { AuthEventService } from '../../../src/services/authEventService.js';

// ---- helpers ----

const mockReq = {} as any;
const inviteTokenHash = createBootstrapInviteTokenHash('token');

const baseUser = () =>
  ({
    id: 'user-1',
    email: 'test@example.com',
    roles: ['user'],
    save: vi.fn(),
  }) as any;

const validInvite = () => ({
  id: 'invite-1',
  email: 'test@example.com',
  expiresAt: new Date(Date.now() + 10000),
  consumedAt: null,
});

beforeEach(() => {
  vi.clearAllMocks();

  process.env.SEAMLESS_BOOTSTRAP_ENABLED = 'true';

  (getSequelize as any).mockReturnValue({
    transaction: async (fn: any) => fn({}),
  });

  (User.count as any).mockResolvedValue(0);
  (BootstrapInvite.update as any).mockResolvedValue([1]);
});

it('returns bootstrap_disabled when feature off', async () => {
  process.env.SEAMLESS_BOOTSTRAP_ENABLED = 'false';

  const result = await maybePromoteBootstrapAdmin({
    user: baseUser(),
    req: mockReq,
    completionMethod: 'webauthn_registration',
  });

  expect(result).toEqual({
    promoted: false,
    reason: 'bootstrap_disabled',
  });
});

it('skips if user already admin', async () => {
  const user = baseUser();
  user.roles = ['admin'];

  const result = await maybePromoteBootstrapAdmin({
    user,
    req: mockReq,
    completionMethod: 'webauthn_registration',
  });

  expect(result).toEqual({
    promoted: false,
    reason: 'already_admin',
  });
});

it('skips if user already has admin write scope', async () => {
  const user = baseUser();
  user.roles = ['admin:write'];

  const result = await maybePromoteBootstrapAdmin({
    user,
    req: mockReq,
    completionMethod: 'webauthn_registration',
  });

  expect(result).toEqual({
    promoted: false,
    reason: 'already_admin',
  });
});

it('returns missing_token when no invite token hash is present', async () => {
  const result = await maybePromoteBootstrapAdmin({
    user: baseUser(),
    req: mockReq,
    completionMethod: 'webauthn_registration',
  });

  expect(result).toEqual({
    promoted: false,
    reason: 'missing_token',
  });
});

it('returns invalid_token when invite not found', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue(null);

  const result = await maybePromoteBootstrapAdmin({
    user: baseUser(),
    req: mockReq,
    completionMethod: 'webauthn_registration',
    bootstrapInviteTokenHash: inviteTokenHash,
  });

  expect(result.reason).toBe('invalid_token');
});

it('returns invite_consumed when already used', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue({
    ...validInvite(),
    consumedAt: new Date(),
  });

  const result = await maybePromoteBootstrapAdmin({
    user: baseUser(),
    req: mockReq,
    completionMethod: 'webauthn_registration',
    bootstrapInviteTokenHash: inviteTokenHash,
  });

  expect(result.reason).toBe('invite_consumed');
});

it('returns invite_expired when expired', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue({
    ...validInvite(),
    expiresAt: new Date(Date.now() - 1000),
  });

  const result = await maybePromoteBootstrapAdmin({
    user: baseUser(),
    req: mockReq,
    completionMethod: 'webauthn_registration',
    bootstrapInviteTokenHash: inviteTokenHash,
  });

  expect(result.reason).toBe('invite_expired');
});

it('returns email_mismatch when emails differ', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue({
    ...validInvite(),
    email: 'other@example.com',
  });

  const result = await maybePromoteBootstrapAdmin({
    user: baseUser(),
    req: mockReq,
    completionMethod: 'webauthn_registration',
    bootstrapInviteTokenHash: inviteTokenHash,
  });

  expect(result.reason).toBe('email_mismatch');
});

it('returns admin_exists when admin already present', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue(validInvite());

  (User.count as any).mockResolvedValue(1);

  const result = await maybePromoteBootstrapAdmin({
    user: baseUser(),
    req: mockReq,
    completionMethod: 'webauthn_registration',
    bootstrapInviteTokenHash: inviteTokenHash,
  });

  expect(result.reason).toBe('admin_exists');
});

it('returns invite_consumed if update fails (race condition)', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue(validInvite());

  (BootstrapInvite.update as any).mockResolvedValue([0]);

  const user = baseUser();

  const result = await maybePromoteBootstrapAdmin({
    user,
    req: mockReq,
    completionMethod: 'webauthn_registration',
    bootstrapInviteTokenHash: inviteTokenHash,
  });

  expect(result.reason).toBe('invite_consumed');
});

it('promotes user to admin successfully', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue(validInvite());

  const user = baseUser();

  const result = await maybePromoteBootstrapAdmin({
    user,
    req: mockReq,
    completionMethod: 'webauthn_registration',
    bootstrapInviteTokenHash: inviteTokenHash,
  });

  expect(result).toEqual({
    promoted: true,
    reason: 'success',
  });

  expect(user.roles).toContain('admin');
  expect(user.save).toHaveBeenCalled();

  expect(BootstrapInvite.update).toHaveBeenCalled();

  expect(AuthEventService.log).toHaveBeenCalledWith(
    expect.objectContaining({
      type: 'bootstrap_admin_granted',
    }),
  );
});
