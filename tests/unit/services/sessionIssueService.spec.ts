import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  BreakGlassFactorError,
  issueSessionAndRespond,
  PasskeyRequiredError,
} from '../../../src/services/sessionIssuance.js';

vi.mock('../../../src/lib/token.js', () => ({
  generateRefreshToken: vi.fn(),
  createRefreshTokenLookup: vi.fn(),
  signAccessToken: vi.fn(),
}));

vi.mock('../../../src/models/sessions.js', () => ({
  Session: {
    create: vi.fn(),
  },
}));

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('../../../src/services/organizationService.js', () => ({
  findMembership: vi.fn(async () => ({ roles: [] })),
  getDefaultOrganizationIdForUser: vi.fn(),
}));

vi.mock('../../../src/services/concurrentSessionPolicy.js', () => ({
  enforceConcurrentSessionLimit: vi.fn(),
}));

vi.mock('../../../src/services/loginHookService.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/services/loginHookService.js')>();
  return { ...actual, runLoginHook: vi.fn(async () => ({ outcome: 'skipped' })) };
});

vi.mock('../../../src/utils/utils.js', () => ({
  computeSessionTimes: vi.fn(),
  parseDurationToSeconds: vi.fn(),
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  signAccessToken,
} from '../../../src/lib/token.js';
import { Session } from '../../../src/models/sessions.js';
import { enforceConcurrentSessionLimit } from '../../../src/services/concurrentSessionPolicy.js';
import { runLoginHook } from '../../../src/services/loginHookService.js';
import { getDefaultOrganizationIdForUser } from '../../../src/services/organizationService.js';
import { computeSessionTimes, parseDurationToSeconds } from '../../../src/utils/utils.js';

const mockReq = () =>
  ({
    get: vi.fn().mockReturnValue('test-agent'),
    ip: '127.0.0.1',
  }) as any;

const mockRes = () => {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
};

const mockUser = {
  id: 'user-1',
  email: 'test@example.com',
  phone: '+1234567890',
  roles: ['user'],
};

beforeEach(() => {
  vi.clearAllMocks();

  (generateRefreshToken as any).mockReturnValue('refresh-token');
  (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
  (signAccessToken as any).mockResolvedValue('access-token');

  (Session.create as any).mockResolvedValue({ id: 'session-1' });

  (computeSessionTimes as any).mockReturnValue({
    expiresAt: new Date(),
    idleExpiresAt: new Date(),
  });

  (getSystemConfig as any).mockResolvedValue({
    access_token_ttl: '15m',
    refresh_token_ttl: '1h',
    session_idle_ttl: '8h',
    max_concurrent_sessions: null,
  });

  (parseDurationToSeconds as any).mockImplementation((v: string) => (v === '15m' ? 900 : 3600));
  (getDefaultOrganizationIdForUser as any).mockResolvedValue(null);
  vi.mocked(runLoginHook).mockResolvedValue({ outcome: 'skipped' });
});

describe('issueSessionAndRespond', () => {
  it('issues a bearer/json session response', async () => {
    const req = mockReq();
    const res = mockRes();

    await issueSessionAndRespond({
      user: mockUser,
      req,
      res,
    });

    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: 'server',
        refreshTokenLookup: 'refresh-lookup',
      }),
    );
    expect(signAccessToken).toHaveBeenCalledWith('session-1', mockUser.id, mockUser.roles, null, {
      recovery: false,
      authorization: { permissions: [] },
      customClaims: {},
    });
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      message: 'Success',
      token: 'access-token',
      refreshToken: 'refresh-token',
      sub: mockUser.id,
      organizationId: null,
      roles: mockUser.roles,
      email: mockUser.email,
      phone: mockUser.phone,
      ttl: 900,
      refreshTtl: 3600,
    });
  });

  // The one record that a sign-in completed, which the user.signed_in webhook is built from.
  it('records that a session was created, with the method and organization', async () => {
    const req = mockReq();

    await issueSessionAndRespond({ user: mockUser, req, res: mockRes(), method: 'email_otp' });

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: mockUser.id,
        sessionId: 'session-1',
        type: 'session_created',
        metadata: { method: 'email_otp', organizationId: null },
      }),
    );
  });

  it('marks a recovery session in the record', async () => {
    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res: mockRes(),
      method: 'account_recovery',
      recovery: true,
    });

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'session_created',
        metadata: expect.objectContaining({ recovery: true }),
      }),
    );
  });

  it('records the sign-in method and time for the provider auth context', async () => {
    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res: mockRes(),
      method: 'passkey',
      passkey: { deviceBound: true, userVerified: true },
    });

    const created = (Session.create as any).mock.calls[0][0];
    expect(created.authMethods).toEqual([
      {
        method: 'passkey',
        at: created.authTime.toISOString(),
        deviceBound: true,
        userVerified: true,
      },
    ]);
  });

  it('records no passkey flags for another method, and nothing for account recovery', async () => {
    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res: mockRes(),
      method: 'email_otp',
      passkey: { deviceBound: true, userVerified: true },
    });
    expect((Session.create as any).mock.calls[0][0].authMethods).toEqual([
      { method: 'email_otp', at: expect.any(String) },
    ]);

    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res: mockRes(),
      method: 'account_recovery',
      recovery: true,
    });
    expect((Session.create as any).mock.calls[1][0].authMethods).toEqual([]);
  });

  it('derives the session bounds from configured TTLs', async () => {
    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    expect(computeSessionTimes).toHaveBeenCalledWith(
      { absoluteTtl: '1h', idleTtl: '8h' },
      expect.any(Date),
    );
  });

  it('starts a new rotation chain at the time the bounds are measured from', async () => {
    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    const measuredFrom = (computeSessionTimes as any).mock.calls[0][1];
    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({ chainStartedAt: measuredFrom }),
    );
  });

  it('falls back to a default idle bound when config omits it', async () => {
    (getSystemConfig as any).mockResolvedValue({ refresh_token_ttl: '1h' });

    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    expect(computeSessionTimes).toHaveBeenCalledWith(
      { absoluteTtl: '1h', idleTtl: '8h' },
      expect.any(Date),
    );
  });

  describe('with passkey fallback off', () => {
    beforeEach(() => {
      (getSystemConfig as any).mockResolvedValue({
        access_token_ttl: '15m',
        refresh_token_ttl: '1h',
        session_idle_ttl: '8h',
        login_methods: ['passkey', 'email_otp', 'oauth'],
        passkey_login_fallback_enabled: false,
      });
    });

    it.each(['email_otp', 'phone_otp', 'magic_link', 'totp', 'oauth'] as const)(
      'refuses to start a session from %s for an account that holds a passkey',
      async (method) => {
        (Credential.count as any).mockResolvedValue(1);

        await expect(
          issueSessionAndRespond({ method, user: mockUser, req: mockReq(), res: mockRes() }),
        ).rejects.toBeInstanceOf(PasskeyRequiredError);

        expect(Credential.count).toHaveBeenCalledWith({ where: { userId: mockUser.id } });
        expect(Session.create).not.toHaveBeenCalled();
      },
    );

    it('starts a session from another factor for an account with no passkey', async () => {
      (Credential.count as any).mockResolvedValue(0);

      await issueSessionAndRespond({
        method: 'oauth',
        user: mockUser,
        req: mockReq(),
        res: mockRes(),
      });

      expect(Session.create).toHaveBeenCalled();
    });

    it('starts a session from a passkey without counting credentials', async () => {
      await issueSessionAndRespond({
        method: 'passkey',
        user: mockUser,
        req: mockReq(),
        res: mockRes(),
      });

      expect(Credential.count).not.toHaveBeenCalled();
      expect(Session.create).toHaveBeenCalled();
    });
  });

  describe('in phishing-resistant-only mode', () => {
    beforeEach(() => {
      (getSystemConfig as any).mockResolvedValue({
        access_token_ttl: '15m',
        refresh_token_ttl: '1h',
        session_idle_ttl: '8h',
        login_methods: ['passkey'],
        phishing_resistant_only: true,
      });
    });

    it.each(['email_otp', 'phone_otp', 'magic_link', 'totp', 'oauth'] as const)(
      'refuses to start a session from %s even if an endpoint let it through',
      async (method) => {
        await expect(
          issueSessionAndRespond({ method, user: mockUser, req: mockReq(), res: mockRes() }),
        ).rejects.toBeInstanceOf(PasskeyRequiredError);

        expect(Session.create).not.toHaveBeenCalled();
      },
    );

    it('starts a restricted recovery session, which is how a user gets a passkey back', async () => {
      const res = mockRes();

      await issueSessionAndRespond({
        method: 'recovery_code',
        recovery: true,
        user: mockUser,
        req: mockReq(),
        res,
      });

      expect(Session.create).toHaveBeenCalledWith(expect.objectContaining({ recovery: true }));
      expect(signAccessToken).toHaveBeenCalledWith('session-1', mockUser.id, mockUser.roles, null, {
        recovery: true,
        authorization: { permissions: [] },
        customClaims: {},
      });
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ recovery: true, nextStep: 'enroll_passkey' }),
      );
    });

    it('starts a session from a passkey', async () => {
      await issueSessionAndRespond({
        method: 'passkey',
        user: mockUser,
        req: mockReq(),
        res: mockRes(),
      });

      expect(Session.create).toHaveBeenCalled();
    });

    describe('for a break-glass admin', () => {
      const breakGlassUser = { ...mockUser, email: 'Root@Example.com', roles: ['admin:write'] };

      beforeEach(() => {
        vi.stubEnv('BREAK_GLASS_EMAILS', 'root@example.com');
      });

      afterEach(() => {
        vi.unstubAllEnvs();
      });

      it.each(['passkey', 'totp', 'recovery_code'] as const)(
        'starts a session from %s, which policy cannot take away',
        async (method) => {
          await issueSessionAndRespond({
            method,
            user: breakGlassUser,
            req: mockReq(),
            res: mockRes(),
          });

          expect(Session.create).toHaveBeenCalled();
        },
      );

      it.each(['email_otp', 'phone_otp', 'magic_link', 'oauth'] as const)(
        'refuses %s, which proves only an address or an outside identity',
        async (method) => {
          await expect(
            issueSessionAndRespond({
              method,
              user: breakGlassUser,
              req: mockReq(),
              res: mockRes(),
            }),
          ).rejects.toBeInstanceOf(BreakGlassFactorError);

          expect(Session.create).not.toHaveBeenCalled();
        },
      );

      it('gives a listed account without an admin role no exemption', async () => {
        await expect(
          issueSessionAndRespond({
            method: 'totp',
            user: { ...breakGlassUser, roles: ['user'] },
            req: mockReq(),
            res: mockRes(),
          }),
        ).rejects.toBeInstanceOf(PasskeyRequiredError);
      });
    });

    it("starts the one session that completes a new account's address verification", async () => {
      await issueSessionAndRespond({
        method: 'email_otp',
        accountVerification: true,
        user: mockUser,
        req: mockReq(),
        res: mockRes(),
      });

      expect(Session.create).toHaveBeenCalled();
    });
  });

  it('throws if token generation fails', async () => {
    const req = mockReq();
    const res = mockRes();

    (signAccessToken as any).mockResolvedValue(null);

    await expect(
      issueSessionAndRespond({
        user: mockUser,
        req,
        res,
      }),
    ).rejects.toThrow('Failed to issue session tokens');
  });

  it('passes request metadata into session creation', async () => {
    const req = mockReq();
    const res = mockRes();

    await issueSessionAndRespond({
      user: mockUser,
      req,
      res,
    });

    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userAgent: 'test-agent',
        ipAddress: '127.0.0.1',
        organizationId: null,
      }),
    );
  });

  it('stores the default organization when one exists', async () => {
    const req = mockReq();
    const res = mockRes();

    (getDefaultOrganizationIdForUser as any).mockResolvedValue('org-1');

    await issueSessionAndRespond({
      user: mockUser,
      req,
      res,
    });

    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: 'org-1',
      }),
    );
    expect(signAccessToken).toHaveBeenCalledWith(
      'session-1',
      mockUser.id,
      mockUser.roles,
      'org-1',
      {
        recovery: false,
        authorization: { permissions: [], org_roles: [], org_permissions: [] },
        customClaims: {},
      },
    );
  });

  it('uses default TTL values when config missing', async () => {
    const req = mockReq();
    const res = mockRes();

    (getSystemConfig as any).mockResolvedValue({});

    await issueSessionAndRespond({
      user: mockUser,
      req,
      res,
    });

    expect(parseDurationToSeconds).toHaveBeenCalledWith('15m');
    expect(parseDurationToSeconds).toHaveBeenCalledWith('1d');
  });
});

describe('concurrent session limit', () => {
  it('applies the configured limit before the new session is stored', async () => {
    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
      session_idle_ttl: '8h',
      max_concurrent_sessions: 3,
    });

    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    expect(enforceConcurrentSessionLimit).toHaveBeenCalledWith(
      expect.objectContaining({ userId: mockUser.id, limit: 3 }),
    );

    // Ordering is the point: the limit counts the session about to exist, so it
    // has to run before the row is created.
    const evictionOrder = (enforceConcurrentSessionLimit as any).mock.invocationCallOrder[0];
    const createOrder = (Session.create as any).mock.invocationCallOrder[0];
    expect(evictionOrder).toBeLessThan(createOrder);
  });

  it('adds extraFields to the response', async () => {
    const res = mockRes();

    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res,
      extraFields: { returnTo: 'https://app.example.com/dashboard' },
    });

    expect((res.json as any).mock.calls[0][0]).toMatchObject({
      returnTo: 'https://app.example.com/dashboard',
      message: 'Success',
    });
  });

  // The bag is untyped, and it is spread into the one response every authenticated
  // flow returns, so it must not be able to replace any part of the session in it.
  it('does not let extraFields replace the session material', async () => {
    const res = mockRes();

    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res,
      extraFields: { token: 'forged', refreshToken: 'forged', sub: 'someone-else' },
    });

    const body = (res.json as any).mock.calls[0][0];

    expect(body.token).not.toBe('forged');
    expect(body.refreshToken).not.toBe('forged');
    expect(body.sub).toBe(mockUser.id);
  });

  it('passes no limit through when the deployment has not set one', async () => {
    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    expect(enforceConcurrentSessionLimit).toHaveBeenCalledWith(
      expect.objectContaining({ limit: null }),
    );
  });
});

describe('login hooks', () => {
  function hooksAnswer(
    postLogin: Awaited<ReturnType<typeof runLoginHook>>,
    preToken: Awaited<ReturnType<typeof runLoginHook>> = { outcome: 'skipped' },
  ) {
    vi.mocked(runLoginHook).mockImplementation(async (trigger) =>
      trigger === 'post_login' ? postLogin : preToken,
    );
  }

  it('calls post_login then pre_token with the user, method and organization', async () => {
    (getDefaultOrganizationIdForUser as any).mockResolvedValue('org-1');
    const req = mockReq();

    expect(
      await issueSessionAndRespond({ user: mockUser, req, res: mockRes(), method: 'passkey' }),
    ).toBe(true);

    expect(vi.mocked(runLoginHook).mock.calls.map(([trigger]) => trigger)).toEqual([
      'post_login',
      'pre_token',
    ]);
    expect(runLoginHook).toHaveBeenCalledWith('post_login', {
      user: mockUser,
      method: 'passkey',
      organizationId: 'org-1',
      req,
    });
  });

  it('answers a deny with 403 and the hook message, and creates no session', async () => {
    hooksAnswer({ outcome: 'denied', userMessage: 'Your account is on hold.' });
    const res = mockRes();

    const issued = await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res,
      method: 'passkey',
    });

    expect(issued).toBe(false);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      error: 'login_denied',
      message: 'Your account is on hold.',
    });
    expect(runLoginHook).toHaveBeenCalledTimes(1);
    expect(enforceConcurrentSessionLimit).not.toHaveBeenCalled();
    expect(Session.create).not.toHaveBeenCalled();
    expect(signAccessToken).not.toHaveBeenCalled();
  });

  it('answers a closed failure with 503 and creates no session', async () => {
    hooksAnswer({ outcome: 'allowed', claims: null }, { outcome: 'failed_closed' });
    const res = mockRes();

    expect(
      await issueSessionAndRespond({ user: mockUser, req: mockReq(), res, method: 'totp' }),
    ).toBe(false);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith({ error: 'login_hook_unavailable' });
    expect(Session.create).not.toHaveBeenCalled();
  });

  it('keeps the pre_token claims on the session and puts them in the token', async () => {
    hooksAnswer(
      { outcome: 'allowed', claims: null },
      { outcome: 'allowed', claims: { plan: 'pro' } },
    );

    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res: mockRes(),
      method: 'passkey',
    });

    expect(Session.create).toHaveBeenCalledWith(
      expect.objectContaining({ hookClaims: { plan: 'pro' } }),
    );
    expect(signAccessToken).toHaveBeenCalledWith('session-1', mockUser.id, mockUser.roles, null, {
      recovery: false,
      authorization: { permissions: [] },
      customClaims: { plan: 'pro' },
    });
  });

  it('signs in without claims when pre_token fails open', async () => {
    hooksAnswer({ outcome: 'allowed', claims: null }, { outcome: 'failed_open' });

    expect(
      await issueSessionAndRespond({
        user: mockUser,
        req: mockReq(),
        res: mockRes(),
        method: 'passkey',
      }),
    ).toBe(true);
    expect(Session.create).toHaveBeenCalledWith(expect.objectContaining({ hookClaims: null }));
  });

  it('still calls hooks for the session that completes account verification', async () => {
    await issueSessionAndRespond({
      user: mockUser,
      req: mockReq(),
      res: mockRes(),
      method: 'email_otp',
      accountVerification: true,
    });

    expect(runLoginHook).toHaveBeenCalledTimes(2);
  });

  it('never calls a hook for a recovery session', async () => {
    hooksAnswer({ outcome: 'failed_closed' }, { outcome: 'failed_closed' });

    expect(
      await issueSessionAndRespond({
        user: mockUser,
        req: mockReq(),
        res: mockRes(),
        method: 'account_recovery',
        recovery: true,
      }),
    ).toBe(true);
    expect(runLoginHook).not.toHaveBeenCalled();
    expect(Session.create).toHaveBeenCalledWith(expect.objectContaining({ hookClaims: null }));
  });

  it('never calls a hook for a break-glass administrator', async () => {
    vi.stubEnv('BREAK_GLASS_EMAILS', 'root@example.com');
    hooksAnswer({ outcome: 'failed_closed' }, { outcome: 'failed_closed' });

    expect(
      await issueSessionAndRespond({
        user: { ...mockUser, email: 'root@example.com', roles: ['admin:write'] },
        req: mockReq(),
        res: mockRes(),
        method: 'passkey',
      }),
    ).toBe(true);
    expect(runLoginHook).not.toHaveBeenCalled();
  });
});
