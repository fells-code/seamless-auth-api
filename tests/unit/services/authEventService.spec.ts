import { vi } from 'vitest';
vi.unmock('../../../src/services/authEventService');
vi.unmock('../../../src/models/authEvents');
vi.unmock('../../../src/utils/logger');

vi.mock('../../../src/models/authEvents', () => ({
  AuthEvent: {
    create: vi.fn(),
  },
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
    const { AuthEvent } = await import('../../../src/models/authEvents');
    const { AuthEventService } = await import('../../../src/services/authEventService');

    const req = buildReq();

    await AuthEventService.log({
      userId: 'user-1',
      type: 'login_success',
      req,
    });

    expect(AuthEvent.create).toHaveBeenCalledWith({
      user_id: 'user-1',
      type: 'login_success',
      ip_address: '127.0.0.1',
      user_agent: 'agent',
      metadata: null,
    });
  });

  it('handles missing ip and user-agent', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents');
    const { AuthEventService } = await import('../../../src/services/authEventService');

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

  it.skip('swallows errors and logs failure', async () => {
    const { AuthEvent } = await import('../../../src/models/authEvents');
    const getLogger = (await import('../../../src/utils/logger')).default('test');

    const { AuthEventService } = await import('../../../src/services/authEventService');

    (AuthEvent.create as any).mockRejectedValue(new Error('fail'));

    const req = buildReq();

    await AuthEventService.log({
      type: 'login_success',
      req,
    });

    expect(getLogger.error).toHaveBeenCalled();
  });

  it('loginSuccess calls log', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService');

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
    const { AuthEventService } = await import('../../../src/services/authEventService');

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
    const { AuthEventService } = await import('../../../src/services/authEventService');

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
    const { AuthEventService } = await import('../../../src/services/authEventService');

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
    const { AuthEventService } = await import('../../../src/services/authEventService');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.notificationSent('user-1', req);

    expect(spy).toHaveBeenCalled();
  });

  it('serviceTokenUsed logs correct metadata', async () => {
    const { AuthEventService } = await import('../../../src/services/authEventService');

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
    const { AuthEventService } = await import('../../../src/services/authEventService');

    const spy = vi.spyOn(AuthEventService, 'log');

    const req = buildReq();

    await AuthEventService.serviceTokenInvalid(req);

    expect(spy).toHaveBeenCalledWith({
      type: 'service_token_failed',
      metadata: null,
      req,
    });
  });
});
