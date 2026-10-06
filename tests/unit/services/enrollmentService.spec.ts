import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';
import { getSequelize } from '../../../src/models/index.js';
import { User } from '../../../src/models/users.js';
import { DeliveryError } from '../../../src/services/deliveryError.js';
import {
  EnrollmentInviteError,
  enrollmentStatus,
  inviteToEnroll,
  listEnrollment,
  passkeyEnrollmentPrompt,
} from '../../../src/services/enrollmentService.js';
import { getLoginPolicy } from '../../../src/services/loginPolicyService.js';
import { sendEnrollmentInviteEmail } from '../../../src/services/messagingService.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

vi.mock('../../../src/services/loginPolicyService.js', () => ({
  getLoginPolicy: vi.fn(),
}));

const query = vi.fn();
const sqlFor = (fragment: string) =>
  query.mock.calls.find(([sql]) => String(sql).includes(fragment));

const config = {
  prompt_passkey_enrollment: false,
  origins: ['https://app.example.com'],
  frontend_url: 'https://app.example.com',
  oauth_providers: [],
};

function row(overrides: Record<string, unknown> = {}) {
  return {
    id: 'u-1',
    email: 'ada@example.com',
    imported: true,
    credentialCount: 0,
    lastLogin: null,
    enrollmentInvitedAt: null,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  vi.mocked(getSystemConfig).mockResolvedValue(config as never);
  vi.mocked(getLoginPolicy).mockResolvedValue({
    loginMethods: ['passkey', 'email_otp'],
    passkeyFallbackEnabled: true,
  } as never);
  vi.mocked(User.update as never as (...args: unknown[]) => unknown).mockResolvedValue([1]);
});

describe('passkeyEnrollmentPrompt', () => {
  it('asks nothing while the tenant has not turned it on', async () => {
    expect(await passkeyEnrollmentPrompt('u-1')).toEqual({});
    expect(Credential.count).not.toHaveBeenCalled();
  });

  it('asks a user with no passkey to enroll one', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({
      ...config,
      prompt_passkey_enrollment: true,
    } as never);
    vi.mocked(Credential.count).mockResolvedValue(0 as never);

    expect(await passkeyEnrollmentPrompt('u-1')).toEqual({ nextStep: 'enroll_passkey' });
  });

  it('asks nothing of a user who already has one', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({
      ...config,
      prompt_passkey_enrollment: true,
    } as never);
    vi.mocked(Credential.count).mockResolvedValue(1 as never);

    expect(await passkeyEnrollmentPrompt('u-1')).toEqual({});
  });
});

describe('enrollmentStatus', () => {
  it.each([
    [0, 'none'],
    [1, 'one'],
    [2, 'two_or_more'],
    [5, 'two_or_more'],
  ])('counts %i credentials as %s', (count, status) => {
    expect(enrollmentStatus(count)).toBe(status);
  });
});

describe('listEnrollment', () => {
  it('summarises every matching user and pages the filtered ones', async () => {
    query.mockImplementation(async (sql: string) =>
      sql.includes('FILTER')
        ? [{ total: 5, none: 3, one: 1, twoOrMore: 1, filtered: 3 }]
        : [row(), row({ id: 'u-2', email: 'bo@example.com', credentialCount: 0 })],
    );

    const result = await listEnrollment({
      limit: 50,
      offset: 0,
      organizationId: 'org-1',
      status: 'none',
      imported: true,
      search: '50%_off',
    });

    expect(result.summary).toEqual({ total: 5, none: 3, one: 1, twoOrMore: 1 });
    expect(result.total).toBe(3);
    expect(result.users[0]).toMatchObject({ id: 'u-1', status: 'none', imported: true });

    const [listSql, listOptions] = sqlFor('LIMIT :limit')!;
    expect(listSql).toContain('m.organization_id = :organizationId');
    expect(listSql).toContain('EXISTS (SELECT 1 FROM user_external_ids');
    expect(listSql).toContain('WHERE "credentialCount" = 0');
    expect(listSql).toContain('u.revoked = false');
    // LIKE wildcards in the search term are matched literally.
    expect(listOptions.replacements).toMatchObject({
      organizationId: 'org-1',
      search: '%50\\%\\_off%',
      limit: 50,
      offset: 0,
    });
  });

  it('lists everyone, without an organization join, when no filters are given', async () => {
    query.mockResolvedValue([]);

    const result = await listEnrollment({ limit: 10, offset: 0 });

    expect(result.summary).toEqual({ total: 0, none: 0, one: 0, twoOrMore: 0 });
    expect(sqlFor('LIMIT :limit')![0]).not.toContain('organization_memberships');
  });
});

describe('inviteToEnroll', () => {
  it('sends to the eligible users and reports why the others were skipped', async () => {
    const recently = new Date(Date.now() - 60 * 60 * 1000);
    query.mockResolvedValue([
      row({ id: 'u-1' }),
      row({ id: 'u-2', credentialCount: 1 }),
      row({ id: 'u-3', enrollmentInvitedAt: recently }),
      row({ id: 'u-4', email: 'bounce@example.com' }),
    ]);
    vi.mocked(sendEnrollmentInviteEmail).mockImplementation(async (to: string) => {
      if (to === 'bounce@example.com') throw new DeliveryError('boom', new Error('ses'));
    });

    const result = await inviteToEnroll(
      { userIds: ['u-1', 'u-2', 'u-3', 'u-4', 'u-9'], status: 'none' },
      { external: false },
    );

    expect(result.results).toEqual([
      { userId: 'u-1', status: 'sent' },
      { userId: 'u-2', status: 'skipped', reason: 'already_enrolled' },
      { userId: 'u-3', status: 'skipped', reason: 'recently_invited' },
      { userId: 'u-4', status: 'skipped', reason: 'delivery_failed' },
      { userId: 'u-9', status: 'skipped', reason: 'not_found' },
    ]);
    expect(result).toMatchObject({ sent: 1, skipped: 4, invitedUserIds: ['u-1'] });
    expect(result).not.toHaveProperty('remaining');
    expect(sendEnrollmentInviteEmail).toHaveBeenCalledWith(
      'ada@example.com',
      'https://app.example.com/login',
    );
    expect(User.update).toHaveBeenCalledWith(
      { enrollmentInvitedAt: expect.any(Date) },
      { where: { id: ['u-1'] } },
    );
  });

  it('hands back the delivery instead of sending in external mode', async () => {
    query.mockResolvedValue([row()]);

    const result = await inviteToEnroll(
      { userIds: ['u-1'], status: 'none', signInUrl: 'https://app.example.com/sign-in' },
      { external: true },
    );

    expect(result.results).toEqual([
      {
        userId: 'u-1',
        status: 'sent',
        delivery: {
          kind: 'enrollment_invite_email',
          to: 'ada@example.com',
          signInUrl: 'https://app.example.com/sign-in',
        },
      },
    ]);
    expect(sendEnrollmentInviteEmail).not.toHaveBeenCalled();
  });

  it('invites an organization in batches and says how many are left', async () => {
    query.mockImplementation(async (sql: string) =>
      sql.includes('COUNT(*)::int AS count') ? [{ count: 250 }] : [row(), row({ id: 'u-2' })],
    );

    const result = await inviteToEnroll(
      { organizationId: 'org-1', status: 'one' },
      { external: false },
    );

    expect(result).toMatchObject({ sent: 2, remaining: 248 });
    const [, options] = sqlFor('LIMIT :limit')!;
    expect(options.replacements).toMatchObject({
      organizationId: 'org-1',
      maxCredentials: 1,
      limit: 200,
      resendBefore: expect.any(Date),
    });
  });

  it('refuses when nothing but passkey can sign a user in', async () => {
    vi.mocked(getLoginPolicy).mockResolvedValue({
      loginMethods: ['passkey', 'oauth'],
      passkeyFallbackEnabled: true,
    } as never);

    await expect(
      inviteToEnroll({ userIds: ['u-1'], status: 'none' }, { external: false }),
    ).rejects.toMatchObject({ status: 409 });
    expect(query).not.toHaveBeenCalled();
  });

  it('accepts OAuth as the way in when a provider is enabled', async () => {
    vi.mocked(getLoginPolicy).mockResolvedValue({
      loginMethods: ['passkey', 'oauth'],
      passkeyFallbackEnabled: true,
    } as never);
    vi.mocked(getSystemConfig).mockResolvedValue({
      ...config,
      oauth_providers: [{ id: 'legacy', enabled: true }],
    } as never);
    query.mockResolvedValue([row()]);

    const result = await inviteToEnroll({ userIds: ['u-1'], status: 'none' }, { external: false });

    expect(result.sent).toBe(1);
  });

  it('refuses a sign-in URL off the tenant origins', async () => {
    const error = await inviteToEnroll(
      { userIds: ['u-1'], status: 'none', signInUrl: 'https://evil.example/login' },
      { external: false },
    ).catch((caught) => caught);

    expect(error).toBeInstanceOf(EnrollmentInviteError);
    expect(error.status).toBe(400);
  });

  it('needs a sign-in URL when the tenant has neither a frontend URL nor an origin', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue({
      ...config,
      frontend_url: undefined,
      origins: [],
    } as never);

    await expect(
      inviteToEnroll({ userIds: ['u-1'], status: 'none' }, { external: false }),
    ).rejects.toMatchObject({ status: 400 });
  });

  it('lets an unexpected send failure through rather than reporting it as a skip', async () => {
    query.mockResolvedValue([row()]);
    vi.mocked(sendEnrollmentInviteEmail).mockRejectedValueOnce(new Error('bug'));

    await expect(
      inviteToEnroll({ userIds: ['u-1'], status: 'none' }, { external: false }),
    ).rejects.toThrow('bug');
    expect(User.update).not.toHaveBeenCalled();
  });
});

describe('listEnrollment filters', () => {
  it('can list only users who were not imported', async () => {
    query.mockResolvedValue([]);

    await listEnrollment({ limit: 10, offset: 0, imported: false });

    expect(sqlFor('LIMIT :limit')![0]).toContain('NOT EXISTS (SELECT 1 FROM user_external_ids');
  });
});
