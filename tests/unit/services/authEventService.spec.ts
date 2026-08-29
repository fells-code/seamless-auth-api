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

import { describe, it, expect, beforeEach } from 'vitest';

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
      type: 'login_success',
      ip_address: '127.0.0.1',
      user_agent: 'agent',
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

  it('swallows errors and logs failure', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents.js');
    const getLogger = (await import('../../../src/utils/logger.js')).default;

    const { AuthEventService } = await import('../../../src/services/authEventService.js');

    (AuthEvent.create as any).mockRejectedValue(new Error('fail'));

    const req = buildReq();

    await AuthEventService.log({
      type: 'login_success',
      req,
    });

    expect(getLogger).toHaveBeenCalledWith('authEventService');
    expect(getLogger.mock.results[0]?.value.error).toHaveBeenCalled();
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
      type: 'request_suspicious',
      ip_address: '10.0.0.1',
      user_agent: 'probe',
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
      type: 'request_suspicious',
      ip_address: '127.0.0.1',
      user_agent: 'agent',
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
