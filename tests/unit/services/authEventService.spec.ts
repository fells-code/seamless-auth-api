import { vi } from 'vitest';
vi.unmock('../../../src/services/authEventService');
vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: {
    create: vi.fn(),
  },
}));

vi.mock('../../../src/utils/logger.js', () => ({
  default: vi.fn(() => ({
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  })),
}));

function buildReq(overrides: any = {}) {
  return {
    ip: '127.0.0.1',
    headers: {
      'user-agent': 'agent',
    },
    ...overrides,
  } as any;
}

import { afterEach, describe, it, expect, beforeEach } from 'vitest';

describe('AuthEventService', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('logs event successfully', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const req = buildReq();

    await AuthEventService.log({
      userId: 'user-1',
      type: 'login_success',
      req,
    });

    expect(AuthEvent.create).toHaveBeenCalledWith({
      user_id: 'user-1',
      actor_user_id: null,
      session_id: null,
      type: 'login_success',
      ip_address: '127.0.0.1',
      user_agent: 'agent',
      deployment_id: null,
      device_class: 'unknown',
      mail_provider: null,
      owner: null,
      attempt_id: null,
      metadata: null,
    });
  });

  it('handles missing ip and user-agent', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const req = { headers: {} } as any;

    await AuthEventService.log({
      type: 'login_success',
      req,
    });

    expect(AuthEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        ip_address: 'unknown',
        user_agent: 'unknown',
      }),
    );
  });

  // Still swallowed: 137 call sites await this, many from inside error handlers,
  // so throwing would turn a bookkeeping failure into a failed request. It is no
  // longer silent, though, which is the part NIST 800-53 AU-5 asks for.
  it('swallows a failed write but reports the instance as degraded', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { getAuditHealth, resetAuditHealthForTests } =
      await import('../../../src/services/auditHealth.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    resetAuditHealthForTests();
    (AuthEvent.create as any).mockRejectedValue(new Error('fail'));

    await expect(
      AuthEventService.log({ type: 'login_success', req: buildReq() }),
    ).resolves.toBeUndefined();

    expect(getAuditHealth().degraded).toBe(true);
    expect(getAuditHealth().failureCount).toBe(1);
  });

  it('loginSuccess calls log', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.loginSuccess('user-1', req);

    expect(spy).toHaveBeenCalledWith({
      userId: 'user-1',
      type: 'login_success',
      req,
    });
  });

  it('loginFailed includes reason', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.loginFailed('bad password', null, req);

    expect(spy).toHaveBeenCalledWith({
      userId: null,
      type: 'login_failed',
      req,
      metadata: { reason: 'bad password' },
    });
  });

  it('tokenRotated calls log', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.tokenRotated('user-1', req, { foo: 'bar' });

    expect(spy).toHaveBeenCalledWith({
      userId: 'user-1',
      type: 'service_token_rotated',
      req,
      metadata: { foo: 'bar' },
    });
  });

  it('authActionTake calls log', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.authActionTake('user-1', req);

    expect(spy).toHaveBeenCalledWith({
      userId: 'user-1',
      type: 'auth_action_incremented',
      req,
      metadata: undefined,
    });
  });

  it('notificationSent calls log', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.notificationSent('user-1', req);

    expect(spy).toHaveBeenCalledWith({
      userId: 'user-1',
      type: 'notification_sent',
      req,
      metadata: undefined,
    });
  });

  it('serviceTokenUsed logs correct metadata', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.serviceTokenUsed('client-1', req);

    expect(spy).toHaveBeenCalledWith({
      type: 'service_token_success',
      metadata: { clientId: 'client-1' },
      req,
    });
  });

  it('serviceTokenInvalid logs failure', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.serviceTokenInvalid(req);

    expect(spy).toHaveBeenCalledWith({
      type: 'service_token_failed',
      metadata: null,
      req,
    });
  });

  it('refreshTokenFailed logs refresh failures', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.refreshTokenFailed(req, { reason: 'Missing refresh token' });

    expect(spy).toHaveBeenCalledWith({
      type: 'refresh_token_failed',
      metadata: { reason: 'Missing refresh token' },
      req,
    });
  });

  it('coerces blank context values to unknown', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    await AuthEventService.logContext({
      type: 'login_success',
      ipAddress: '',
      userAgent: '',
    });

    expect(AuthEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        ip_address: 'unknown',
        user_agent: 'unknown',
      }),
    );
  });

  it('refreshTokenFailed defaults metadata to null', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.refreshTokenFailed(req);

    expect(spy).toHaveBeenCalledWith({
      type: 'refresh_token_failed',
      metadata: null,
      req,
    });
  });

  it('requestSuspicious logs with supplied metadata', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.requestSuspicious(req, { reason: 'velocity' });

    expect(spy).toHaveBeenCalledWith({
      type: 'request_suspicious',
      metadata: { reason: 'velocity' },
      req,
    });
  });

  it('requestSuspicious defaults metadata to null', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.requestSuspicious(req);

    expect(spy).toHaveBeenCalledWith({
      type: 'request_suspicious',
      metadata: null,
      req,
    });
  });

  it('requestSuspiciousContext writes an auth event from raw request context', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    await AuthEventService.requestSuspiciousContext(
      { ipAddress: '10.0.0.1', userAgent: 'probe' },
      { reason: 'no session' },
    );

    expect(AuthEvent.create).toHaveBeenCalledWith({
      user_id: null,
      actor_user_id: null,
      session_id: null,
      type: 'request_suspicious',
      ip_address: '10.0.0.1',
      user_agent: 'probe',
      deployment_id: null,
      device_class: 'unknown',
      mail_provider: null,
      owner: null,
      attempt_id: null,
      metadata: { reason: 'no session' },
    });
  });

  it('requestSuspiciousContext falls back to unknown context and null metadata', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    await AuthEventService.requestSuspiciousContext({});

    expect(AuthEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        ip_address: 'unknown',
        user_agent: 'unknown',
        metadata: null,
      }),
    );
  });

  it('normalizes legacy event type aliases', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const req = buildReq();

    await AuthEventService.log({
      type: 'request_suspicous',
      req,
      metadata: { reason: 'legacy typo' },
    });

    expect(AuthEvent.create).toHaveBeenCalledWith({
      user_id: null,
      actor_user_id: null,
      session_id: null,
      type: 'request_suspicious',
      ip_address: '127.0.0.1',
      user_agent: 'agent',
      deployment_id: null,
      device_class: 'unknown',
      mail_provider: null,
      owner: null,
      attempt_id: null,
      metadata: { reason: 'legacy typo' },
    });
  });

  it('redacts sensitive metadata before writing events', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    const req = buildReq();

    await AuthEventService.log({
      type: 'system_config_updated',
      req,
      metadata: {
        before: {
          email: 'user@example.com',
          phone: '+15555550123',
          emailVerificationToken: '111111',
          oauth: {
            clientSecret: 'oauth-secret',
            clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
          },
        },
        after: {
          prf: { salt: 'salt-value', output: 'derived-secret' },
          scopes: ['admin:read'],
        },
        message: 'Token: abc123 user@example.com',
      },
    });

    expect(AuthEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: {
          before: {
            email: '[REDACTED]',
            phone: '[REDACTED]',
            emailVerificationToken: '[REDACTED]',
            oauth: {
              clientSecret: '[REDACTED]',
              clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
            },
          },
          after: {
            prf: '[REDACTED]',
            scopes: ['admin:read'],
          },
          message: 'Token: [REDACTED] [REDACTED]',
        },
      }),
    );
  });
});

describe('AuthEventService session correlation', () => {
  it('takes the session from the request, so call sites do not have to pass it', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    await AuthEventService.log({
      userId: 'user-1',
      type: 'login_success',
      req: buildReq({ sessionId: 'sess-7' }),
    });

    expect(AuthEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: 'sess-7' }),
    );
  });

  it('leaves a pre-auth event uncorrelated', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    await AuthEventService.log({ type: 'login_challenge', req: buildReq() });

    expect(AuthEvent.create).toHaveBeenCalledWith(expect.objectContaining({ session_id: null }));
  });

  it('lets a caller name a session the request does not carry', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    await AuthEventService.log({
      type: 'admin_session_revoked',
      sessionId: 'sess-other',
      req: buildReq({ sessionId: 'sess-admin' }),
    });

    expect(AuthEvent.create).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: 'sess-other' }),
    );
  });

  describe('dimensions', () => {
    const iphone =
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

    afterEach(() => {
      vi.unstubAllEnvs();
    });

    it('stamps the deployment, device class and attempt on every row', async () => {
      vi.stubEnv('APP_ID', 'gen-42');

      const { AuthEvent } = await import('../../../src/models/authEvents.js');
      const { AuthEventService } = await import('../../../src/services/authEventService.js');

      await AuthEventService.log({
        userId: 'user-1',
        type: 'webauthn_login_failed',
        req: buildReq({ headers: { 'user-agent': iphone }, attemptId: 'attempt-1' }),
      });

      expect(AuthEvent.create).toHaveBeenCalledWith(
        expect.objectContaining({
          deployment_id: 'gen-42',
          device_class: 'ios',
          attempt_id: 'attempt-1',
        }),
      );
    });

    it('derives the mail provider and owner flag from the principal when it is the subject', async () => {
      vi.stubEnv('OWNER_EMAIL', 'Owner@Example.com');

      const { AuthEvent } = await import('../../../src/models/authEvents.js');
      const { AuthEventService } = await import('../../../src/services/authEventService.js');

      await AuthEventService.log({
        userId: 'user-1',
        type: 'verify_otp_success',
        req: buildReq({ user: { id: 'user-1', email: 'owner@example.com' } }),
      });

      expect(AuthEvent.create).toHaveBeenCalledWith(
        expect.objectContaining({ mail_provider: 'other', owner: true }),
      );

      await AuthEventService.log({
        userId: 'user-2',
        type: 'verify_otp_success',
        req: buildReq({ user: { id: 'user-2', email: 'friend@gmail.com' } }),
      });

      expect(AuthEvent.create).toHaveBeenLastCalledWith(
        expect.objectContaining({ mail_provider: 'gmail', owner: false }),
      );
    });

    // An administrator acting on another account, and a decoy principal, both say
    // nothing about the subject.
    it('leaves the subject dimensions null when the principal is not the subject', async () => {
      const { AuthEvent } = await import('../../../src/models/authEvents.js');
      const { AuthEventService } = await import('../../../src/services/authEventService.js');

      await AuthEventService.log({
        userId: 'target',
        actorUserId: 'admin',
        type: 'user_deleted',
        req: buildReq({ user: { id: 'admin', email: 'admin@gmail.com' } }),
      });

      expect(AuthEvent.create).toHaveBeenCalledWith(
        expect.objectContaining({ mail_provider: null, owner: null }),
      );

      await AuthEventService.log({
        userId: 'decoy-subject',
        type: 'login_failed',
        req: buildReq({ user: { id: 'decoy-subject', email: 'ghost@gmail.com' }, decoy: true }),
      });

      expect(AuthEvent.create).toHaveBeenLastCalledWith(
        expect.objectContaining({ mail_provider: null, owner: null }),
      );
    });

    it('takes an explicit subject address and attempt over the request', async () => {
      const { AuthEvent } = await import('../../../src/models/authEvents.js');
      const { AuthEventService } = await import('../../../src/services/authEventService.js');

      await AuthEventService.log({
        userId: 'user-1',
        attemptId: 'attempt-2',
        subjectEmail: 'someone@icloud.com',
        type: 'login_success',
        req: buildReq({ attemptId: 'attempt-1' }),
      });

      expect(AuthEvent.create).toHaveBeenCalledWith(
        expect.objectContaining({
          mail_provider: 'icloud',
          owner: false,
          attempt_id: 'attempt-2',
        }),
      );
    });

    it('does not write the subject address anywhere on the row', async () => {
      const { AuthEvent } = await import('../../../src/models/authEvents.js');
      const { AuthEventService } = await import('../../../src/services/authEventService.js');

      await AuthEventService.log({
        userId: 'user-1',
        subjectEmail: 'someone@icloud.com',
        type: 'login_success',
        req: buildReq(),
      });

      const [[row]] = (AuthEvent.create as any).mock.calls;

      expect(JSON.stringify(row)).not.toContain('someone@icloud.com');
    });
  });
});
