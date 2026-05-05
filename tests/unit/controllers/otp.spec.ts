import { beforeEach, describe, expect, it, vi } from 'vitest';

const setAuthCookiesMock = vi.fn();
const signEphemeralTokenMock = vi.fn();
const authEventLogMock = vi.fn();
const issueSessionAndRespondMock = vi.fn();
const generateEmailOTPMock = vi.fn();
const generatePhoneOTPMock = vi.fn();
const verifyEmailOTPMock = vi.fn();
const verifyPhoneOTPMock = vi.fn();
const isValidEmailMock = vi.fn();
const isValidPhoneNumberMock = vi.fn();
const normalizePhoneNumberMock = vi.fn();
const loggerMock = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

vi.mock('../../../src/lib/cookie.js', () => ({
  setAuthCookies: setAuthCookiesMock,
}));

vi.mock('../../../src/lib/token.js', () => ({
  signEphemeralToken: signEphemeralTokenMock,
}));

vi.mock('../../../src/services/authEventService.js', () => ({
  AuthEventService: {
    log: authEventLogMock,
    refreshTokenFailed: vi.fn(),
    requestSuspicious: vi.fn(),
    requestSuspiciousContext: vi.fn(),
  },
}));

vi.mock('../../../src/services/sessionIssuance.js', () => ({
  issueSessionAndRespond: issueSessionAndRespondMock,
}));

vi.mock('../../../src/utils/otp.js', () => ({
  generateEmailOTP: generateEmailOTPMock,
  generatePhoneOTP: generatePhoneOTPMock,
  verifyEmailOTP: verifyEmailOTPMock,
  verifyPhoneOTP: verifyPhoneOTPMock,
}));

vi.mock('../../../src/utils/utils.js', () => ({
  isValidEmail: isValidEmailMock,
  isValidPhoneNumber: isValidPhoneNumberMock,
  normalizePhoneNumber: normalizePhoneNumberMock,
}));

vi.mock('../../../src/utils/logger.js', () => ({
  default: () => loggerMock,
}));

type MockUser = {
  id: string;
  email: string;
  phone: string | null;
  roles: string[];
  verified?: boolean;
  emailVerified?: boolean;
  phoneVerified?: boolean;
  emailVerificationToken?: string;
  emailVerificationTokenExpiry?: Date | null;
  phoneVerificationToken?: string;
  phoneVerificationTokenExpiry?: Date | null;
  update: ReturnType<typeof vi.fn>;
};

function buildUser(overrides: Partial<MockUser> = {}): MockUser {
  return {
    id: 'user-1',
    email: 'test@example.com',
    phone: '+14155552671',
    roles: ['user'],
    verified: true,
    emailVerified: true,
    phoneVerified: true,
    emailVerificationToken: 'EMAILOTP',
    emailVerificationTokenExpiry: new Date(Date.now() + 60_000),
    phoneVerificationToken: '123456',
    phoneVerificationTokenExpiry: new Date(Date.now() + 60_000),
    update: vi.fn(),
    ...overrides,
  };
}

function buildReq(user: MockUser, overrides: Record<string, unknown> = {}) {
  const headers: Record<string, string> = {
    ...(overrides.headers as Record<string, string> | undefined),
  };

  return {
    body: {},
    headers,
    get: vi.fn((name: string) => headers[name.toLowerCase()] ?? headers[name] ?? undefined),
    user,
    ...overrides,
  } as any;
}

function buildRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

async function loadOtpController(authMode: 'web' | 'server' = 'server') {
  vi.resetModules();
  vi.stubEnv('AUTH_MODE', authMode);
  return import('../../../src/controllers/otp.js');
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();

  signEphemeralTokenMock.mockResolvedValue('ephemeral-token');
  generatePhoneOTPMock.mockResolvedValue('654321');
  generateEmailOTPMock.mockResolvedValue('ABCDEF');
  isValidPhoneNumberMock.mockReturnValue(true);
  normalizePhoneNumberMock.mockReturnValue('+14155552671');
  isValidEmailMock.mockReturnValue(true);
});

describe('otp controller', () => {
  it('returns external phone OTP delivery payload in server mode', async () => {
    const { sendPhoneOTP } = await loadOtpController('server');
    const user = buildUser();
    const req = buildReq(user, {
      headers: { 'x-seamless-auth-delivery-mode': 'external' },
    });
    const res = buildRes();

    await sendPhoneOTP(req, res);

    expect(generatePhoneOTPMock).toHaveBeenCalledWith(user, { sendMessage: false });
    expect(signEphemeralTokenMock).toHaveBeenCalledWith(user.id);
    expect(setAuthCookiesMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      message: 'success',
      token: 'ephemeral-token',
      delivery: {
        kind: 'otp_sms',
        to: '+14155552671',
        token: '654321',
      },
    });
  });

  it('rejects phone OTP requests when the user phone is missing', async () => {
    const { sendPhoneOTP } = await loadOtpController('server');
    const user = buildUser({ phone: null });
    const req = buildReq(user);
    const res = buildRes();

    await sendPhoneOTP(req, res);

    expect(authEventLogMock).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: user.id,
        type: 'otp_suspicious',
      }),
    );
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data' });
  });

  it('rejects email OTP requests when the email is invalid', async () => {
    const { sendEmailOTP } = await loadOtpController('server');
    const user = buildUser({ email: 'bad-email' });
    const req = buildReq(user);
    const res = buildRes();
    isValidEmailMock.mockReturnValue(false);

    await sendEmailOTP(req, res);

    expect(generateEmailOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data.' });
  });

  it('sets cookies and returns external email delivery payload in web mode', async () => {
    const { sendEmailOTP } = await loadOtpController('web');
    const user = buildUser();
    const req = buildReq(user, {
      headers: { 'x-seamless-auth-delivery-mode': 'external' },
    });
    const res = buildRes();

    await sendEmailOTP(req, res);

    expect(generateEmailOTPMock).toHaveBeenCalledWith(user, { sendMessage: false });
    expect(setAuthCookiesMock).toHaveBeenCalledWith(res, { ephemeralToken: 'ephemeral-token' });
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      message: 'success',
      delivery: {
        kind: 'otp_email',
        to: user.email,
        token: 'ABCDEF',
      },
    });
  });

  it('returns 401 when phone verification data is missing', async () => {
    const { verifyPhoneNumber } = await loadOtpController('server');
    const user = buildUser({
      phoneVerificationToken: undefined,
      phoneVerificationTokenExpiry: null,
    });
    const req = buildReq(user, {
      body: { verificationToken: '123456' },
    });
    const res = buildRes();

    await verifyPhoneNumber(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Failed to verify OTP' });
  });

  it('returns success without issuing a session when phone verification is partial', async () => {
    const { verifyPhoneNumber } = await loadOtpController('server');
    const verifiedUser = buildUser({
      phoneVerified: true,
      emailVerified: false,
      verified: false,
    });
    const req = buildReq(buildUser(), {
      body: { verificationToken: '123456' },
    });
    const res = buildRes();

    verifyPhoneOTPMock.mockResolvedValue({
      user: verifiedUser,
      verified: true,
    });

    await verifyPhoneNumber(req, res);

    expect(issueSessionAndRespondMock).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
  });

  it('issues a session when login phone verification fully verifies the user', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController('server');
    const verifiedUser = buildUser();
    const req = buildReq(buildUser(), {
      body: { verificationToken: '123456' },
    });
    const res = buildRes();

    verifyPhoneOTPMock.mockResolvedValue({
      user: verifiedUser,
      verified: true,
    });

    await verifyLoginPhoneNumber(req, res);

    expect(issueSessionAndRespondMock).toHaveBeenCalledWith({
      user: {
        id: verifiedUser.id,
        email: verifiedUser.email,
        phone: verifiedUser.phone,
        roles: verifiedUser.roles,
      },
      req,
      res,
      authMode: 'server',
    });
    expect(verifiedUser.update).toHaveBeenCalledWith({
      lastLogin: expect.any(Date),
    });
  });

  it('returns 401 when login phone verification fails', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController('server');
    const failingUser = buildUser();
    const req = buildReq(buildUser(), {
      body: { verificationToken: '123456' },
    });
    const res = buildRes();

    verifyPhoneOTPMock.mockResolvedValue({
      user: failingUser,
      verified: false,
    });

    await verifyLoginPhoneNumber(req, res);

    expect(authEventLogMock).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: failingUser.id,
        type: 'verify_otp_failed',
      }),
    );
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('issues a session when email verification fully verifies the user', async () => {
    const { verifyEmail } = await loadOtpController('server');
    const verifiedUser = buildUser();
    const req = buildReq(buildUser(), {
      body: { verificationToken: 'EMAILOTP' },
    });
    const res = buildRes();

    verifyEmailOTPMock.mockResolvedValue({
      user: verifiedUser,
      verified: true,
    });

    await verifyEmail(req, res);

    expect(issueSessionAndRespondMock).toHaveBeenCalledWith({
      user: {
        id: verifiedUser.id,
        email: verifiedUser.email,
        phone: verifiedUser.phone,
        roles: verifiedUser.roles,
      },
      req,
      res,
      authMode: 'server',
    });
    expect(verifiedUser.update).toHaveBeenCalledWith({
      lastLogin: expect.any(Date),
    });
  });

  it('returns 500 when login email verification fails after lookup succeeds', async () => {
    const { verifyLoginEmail } = await loadOtpController('server');
    const failingUser = buildUser();
    const req = buildReq(buildUser(), {
      body: { verificationToken: 'EMAILOTP' },
    });
    const res = buildRes();

    verifyEmailOTPMock.mockResolvedValue({
      user: failingUser,
      verified: false,
    });

    await verifyLoginEmail(req, res);

    expect(authEventLogMock).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: failingUser.id,
        type: 'verify_otp_failed',
      }),
    );
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
  });
});
