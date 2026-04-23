import { describe, it, expect, vi, beforeEach } from 'vitest';

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

vi.mock('../../../src/lib/cookie.js', () => ({
  setAuthCookies: vi.fn(),
  clearAuthCookies: vi.fn(),
}));

vi.mock('../../../src/lib/bootstrapCookie.js', () => ({
  clearBootstrapCookie: vi.fn(),
}));

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('../../../src/utils/utils.js', () => ({
  computeSessionTimes: vi.fn(),
  parseDurationToSeconds: vi.fn(),
}));

// ---- Imports AFTER mocks ----

import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
} from '../../../src/lib/token.js';

import { Session } from '../../../src/models/sessions.js';
import { setAuthCookies, clearAuthCookies } from '../../../src/lib/cookie.js';
import { clearBootstrapCookie } from '../../../src/lib/bootstrapCookie.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { computeSessionTimes, parseDurationToSeconds } from '../../../src/utils/utils.js';

// ---- Helpers ----

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

// ---- Setup ----

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
  });

  (parseDurationToSeconds as any).mockImplementation((v: string) => (v === '15m' ? 900 : 3600));
});

it('issues session in web mode and sets cookies', async () => {
  const req = mockReq();
  const res = mockRes();

  await issueSessionAndRespond({
    user: mockUser,
    req,
    res,
    authMode: 'web',
  });

  expect(Session.create).toHaveBeenCalled();
  expect(createRefreshTokenLookup).toHaveBeenCalledWith('refresh-token');
  expect(signAccessToken).toHaveBeenCalled();

  expect(setAuthCookies).toHaveBeenCalledWith(res, {
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
  });

  expect(res.status).toHaveBeenCalledWith(200);
  expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
});

it('issues session in server mode and returns JSON payload', async () => {
  const req = mockReq();
  const res = mockRes();

  await issueSessionAndRespond({
    user: mockUser,
    req,
    res,
    authMode: 'server',
  });

  expect(res.status).toHaveBeenCalledWith(200);

  expect(res.json).toHaveBeenCalledWith({
    message: 'Success',
    token: 'access-token',
    refreshToken: 'refresh-token',
    sub: mockUser.id,
    roles: mockUser.roles,
    email: mockUser.email,
    phone: mockUser.phone,
    ttl: 900,
    refreshTtl: 3600,
  });
});

it('clears existing auth cookies when flag set', async () => {
  const req = mockReq();
  const res = mockRes();

  await issueSessionAndRespond({
    user: mockUser,
    req,
    res,
    authMode: 'web',
    clearExistingCookies: true,
  });

  expect(clearAuthCookies).toHaveBeenCalledWith(res);
});

it('clears bootstrap cookie when flag set', async () => {
  const req = mockReq();
  const res = mockRes();

  await issueSessionAndRespond({
    user: mockUser,
    req,
    res,
    authMode: 'web',
    clearBootstrap: true,
  });

  expect(clearBootstrapCookie).toHaveBeenCalledWith(res);
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
      authMode: 'web',
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
    authMode: 'web',
  });

  expect(Session.create).toHaveBeenCalledWith(
    expect.objectContaining({
      userAgent: 'test-agent',
      ipAddress: '127.0.0.1',
    }),
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
    authMode: 'server',
  });

  expect(parseDurationToSeconds).toHaveBeenCalledWith('15m');
  expect(parseDurationToSeconds).toHaveBeenCalledWith('1h');
});
