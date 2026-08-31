import { beforeEach, describe, expect, it, vi } from 'vitest';

import { issueSessionAndRespond } from '../../../src/services/sessionIssuance.js';

vi.mock('../../../src/lib/token.js', () => ({
  generateRefreshToken: vi.fn(),
  hashRefreshToken: vi.fn(),
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
  getDefaultOrganizationIdForUser: vi.fn(),
}));

vi.mock('../../../src/services/concurrentSessionPolicy.js', () => ({
  enforceConcurrentSessionLimit: vi.fn(),
}));

vi.mock('../../../src/utils/utils.js', () => ({
  computeSessionTimes: vi.fn(),
  parseDurationToSeconds: vi.fn(),
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
} from '../../../src/lib/token.js';
import { Session } from '../../../src/models/sessions.js';
import { enforceConcurrentSessionLimit } from '../../../src/services/concurrentSessionPolicy.js';
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
  (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
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
        refreshTokenHash: 'hashed-refresh',
        refreshTokenLookup: 'refresh-lookup',
      }),
    );
    expect(signAccessToken).toHaveBeenCalledWith('session-1', mockUser.id, mockUser.roles, null);
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

  it('derives the session bounds from configured TTLs', async () => {
    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    expect(computeSessionTimes).toHaveBeenCalledWith({
      absoluteTtl: '1h',
      idleTtl: '8h',
    });
  });

  it('falls back to a default idle bound when config omits it', async () => {
    (getSystemConfig as any).mockResolvedValue({ refresh_token_ttl: '1h' });

    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    expect(computeSessionTimes).toHaveBeenCalledWith({
      absoluteTtl: '1h',
      idleTtl: '8h',
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
    expect(signAccessToken).toHaveBeenCalledWith('session-1', mockUser.id, mockUser.roles, 'org-1');
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

  it('passes no limit through when the deployment has not set one', async () => {
    await issueSessionAndRespond({ user: mockUser, req: mockReq(), res: mockRes() });

    expect(enforceConcurrentSessionLimit).toHaveBeenCalledWith(
      expect.objectContaining({ limit: null }),
    );
  });
});
