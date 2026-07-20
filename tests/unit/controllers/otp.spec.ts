import { beforeEach, describe, expect, it, vi } from 'vitest';

import { mintInternalServiceToken } from '../../factories/serviceTokenFactory.js';

const signEphemeralTokenMock = vi.fn();
const authEventLogMock = vi.fn();
const issueSessionAndRespondMock = vi.fn();
const generateEmailOTPMock = vi.fn();
const generatePhoneOTPMock = vi.fn();
const verifyEmailOTPMock = vi.fn();
const verifyPhoneOTPMock = vi.fn();
const getSystemConfigMock = vi.fn();
const isValidEmailMock = vi.fn();
const isValidPhoneNumberMock = vi.fn();
const normalizePhoneNumberMock = vi.fn();
const rejectIfUserLockedMock = vi.fn();
const loggerMock = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

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

vi.mock('../../../src/services/lockoutPolicyService.js', () => ({
  rejectIfUserLocked: rejectIfUserLockedMock,
}));

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: getSystemConfigMock,
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

async function loadOtpController() {
  vi.resetModules();
  return import('../../../src/controllers/otp.js');
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();

  signEphemeralTokenMock.mockResolvedValue('ephemeral-token');
  generatePhoneOTPMock.mockResolvedValue('654321');
  generateEmailOTPMock.mockResolvedValue('ABCDEF');
  getSystemConfigMock.mockResolvedValue({
    login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp'],
    passkey_login_fallback_enabled: true,
  });
  isValidPhoneNumberMock.mockReturnValue(true);
  normalizePhoneNumberMock.mockReturnValue('+14155552671');
  isValidEmailMock.mockReturnValue(true);
  rejectIfUserLockedMock.mockResolvedValue(false);
});

describe('otp controller', () => {
  it('returns external phone OTP delivery payload', async () => {
    const { sendPhoneOTP } = await loadOtpController();
    const user = buildUser();
    const req = buildReq(user, {
      headers: {
        'x-seamless-auth-delivery-mode': 'external',
        'x-seamless-service-token': await mintInternalServiceToken(),
      },
    });
    const res = buildRes();

    await sendPhoneOTP(req, res);

    expect(generatePhoneOTPMock).toHaveBeenCalledWith(user, { sendMessage: false });
    expect(signEphemeralTokenMock).toHaveBeenCalledWith(user.id);
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
    const { sendPhoneOTP } = await loadOtpController();
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
    const { sendEmailOTP } = await loadOtpController();
    const user = buildUser({ email: 'bad-email' });
    const req = buildReq(user);
    const res = buildRes();
    isValidEmailMock.mockReturnValue(false);

    await sendEmailOTP(req, res);

    expect(generateEmailOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data.' });
  });

  it('returns external email OTP delivery payload', async () => {
    const { sendEmailOTP } = await loadOtpController();
    const user = buildUser();
    const req = buildReq(user, {
      headers: {
        'x-seamless-auth-delivery-mode': 'external',
        'x-seamless-service-token': await mintInternalServiceToken(),
      },
    });
    const res = buildRes();

    await sendEmailOTP(req, res);

    expect(generateEmailOTPMock).toHaveBeenCalledWith(user, { sendMessage: false });
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      message: 'success',
      token: 'ephemeral-token',
      delivery: {
        kind: 'otp_email',
        to: user.email,
        token: 'ABCDEF',
      },
    });
  });

  it('rejects disabled login email OTP generation', async () => {
    const { sendLoginEmailOTP } = await loadOtpController();
    const user = buildUser();
    const req = buildReq(user);
    const res = buildRes();

    getSystemConfigMock.mockResolvedValue({
      login_methods: ['passkey', 'magic_link'],
      passkey_login_fallback_enabled: true,
    });

    await sendLoginEmailOTP(req, res);

    expect(generateEmailOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'login_method_disabled' });
  });

  it('returns 401 when phone verification data is missing', async () => {
    const { verifyPhoneNumber } = await loadOtpController();
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
    const { verifyPhoneNumber } = await loadOtpController();
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
    const { verifyLoginPhoneNumber } = await loadOtpController();
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
    });
    expect(verifiedUser.update).toHaveBeenCalledWith({
      lastLogin: expect.any(Date),
    });
  });

  it('rejects disabled login phone OTP verification', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController();
    const req = buildReq(buildUser(), {
      body: { verificationToken: '123456' },
    });
    const res = buildRes();

    getSystemConfigMock.mockResolvedValue({
      login_methods: ['passkey', 'magic_link'],
      passkey_login_fallback_enabled: true,
    });

    await verifyLoginPhoneNumber(req, res);

    expect(verifyPhoneOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'login_method_disabled' });
  });

  it('returns 401 when login phone verification fails', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController();
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
    const { verifyEmail } = await loadOtpController();
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
    });
    expect(verifiedUser.update).toHaveBeenCalledWith({
      lastLogin: expect.any(Date),
    });
  });

  it('returns 401 when login email verification fails after lookup succeeds', async () => {
    const { verifyLoginEmail } = await loadOtpController();
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
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('rejects disabled login email OTP verification', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const req = buildReq(buildUser(), {
      body: { verificationToken: 'EMAILOTP' },
    });
    const res = buildRes();

    getSystemConfigMock.mockResolvedValue({
      login_methods: ['passkey', 'magic_link'],
      passkey_login_fallback_enabled: true,
    });

    await verifyLoginEmail(req, res);

    expect(verifyEmailOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'login_method_disabled' });
  });

  it('returns 401 when the login email verification token is missing', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const req = buildReq(buildUser(), { body: {} });
    const res = buildRes();

    await verifyLoginEmail(req, res);

    expect(verifyEmailOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
    expect(authEventLogMock).toHaveBeenCalledWith(
      expect.objectContaining({ userId: 'user-1', type: 'verify_otp_suspicious' }),
    );
  });

  it('returns 401 when the login email is missing on the user', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const req = buildReq(buildUser({ email: null as unknown as string }), {
      body: { verificationToken: 'EMAILOTP' },
    });
    const res = buildRes();

    await verifyLoginEmail(req, res);

    expect(verifyEmailOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('returns success without a session when login email verification is partial', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const partialUser = buildUser({ emailVerified: true, verified: false });
    const req = buildReq(buildUser(), {
      body: { verificationToken: 'EMAILOTP' },
    });
    const res = buildRes();

    verifyEmailOTPMock.mockResolvedValue({ user: partialUser, verified: true });

    await verifyLoginEmail(req, res);

    expect(issueSessionAndRespondMock).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
  });

  it('issues a session when login email verification fully verifies the user', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const verifiedUser = buildUser();
    const req = buildReq(buildUser(), {
      body: { verificationToken: 'EMAILOTP' },
    });
    const res = buildRes();

    verifyEmailOTPMock.mockResolvedValue({ user: verifiedUser, verified: true });

    await verifyLoginEmail(req, res);

    expect(issueSessionAndRespondMock).toHaveBeenCalledWith({
      user: {
        id: verifiedUser.id,
        email: verifiedUser.email,
        phone: verifiedUser.phone,
        roles: verifiedUser.roles,
      },
      req,
      res,
    });
    expect(verifiedUser.update).toHaveBeenCalledWith({ lastLogin: expect.any(Date) });
    expect(authEventLogMock).toHaveBeenCalledWith(
      expect.objectContaining({ userId: verifiedUser.id, type: 'verify_otp_success' }),
    );
  });

  it('rejects phone OTP when the number is not valid', async () => {
    const { sendPhoneOTP } = await loadOtpController();
    const res = buildRes();
    isValidPhoneNumberMock.mockReturnValue(false);

    await sendPhoneOTP(buildReq(buildUser()), res);

    expect(generatePhoneOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data' });
    expect(authEventLogMock).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'otp_suspicious' }),
    );
  });

  it('returns 500 when phone OTP generation throws an Error', async () => {
    const { sendPhoneOTP } = await loadOtpController();
    const res = buildRes();
    generatePhoneOTPMock.mockRejectedValue(new Error('sms down'));

    await sendPhoneOTP(buildReq(buildUser()), res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
  });

  it('returns 500 when phone OTP generation throws a non-Error', async () => {
    const { sendPhoneOTP } = await loadOtpController();
    const res = buildRes();
    generatePhoneOTPMock.mockRejectedValue('boom');

    await sendPhoneOTP(buildReq(buildUser()), res);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  it('rejects email OTP when the email is missing', async () => {
    const { sendEmailOTP } = await loadOtpController();
    const res = buildRes();

    await sendEmailOTP(buildReq(buildUser({ email: null as unknown as string })), res);

    expect(generateEmailOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data.' });
  });

  it('returns 500 when email OTP generation throws an Error', async () => {
    const { sendEmailOTP } = await loadOtpController();
    const res = buildRes();
    generateEmailOTPMock.mockRejectedValue(new Error('smtp down'));

    await sendEmailOTP(buildReq(buildUser()), res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
  });

  it('returns 500 when email OTP generation throws a non-Error', async () => {
    const { sendEmailOTP } = await loadOtpController();
    const res = buildRes();
    generateEmailOTPMock.mockRejectedValue('boom');

    await sendEmailOTP(buildReq(buildUser()), res);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  it('sends the login phone OTP when phone OTP login is enabled', async () => {
    const { sendLoginPhoneOTP } = await loadOtpController();
    const res = buildRes();

    await sendLoginPhoneOTP(
      buildReq(buildUser(), {
        headers: {
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': await mintInternalServiceToken(),
        },
      }),
      res,
    );

    expect(generatePhoneOTPMock).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
  });

  it('sends the login email OTP when email OTP login is enabled', async () => {
    const { sendLoginEmailOTP } = await loadOtpController();
    const res = buildRes();

    await sendLoginEmailOTP(
      buildReq(buildUser(), {
        headers: {
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': await mintInternalServiceToken(),
        },
      }),
      res,
    );

    expect(generateEmailOTPMock).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
  });

  it('logs a null userId when a disabled login method has no authenticated user', async () => {
    const { sendLoginEmailOTP } = await loadOtpController();
    const res = buildRes();
    getSystemConfigMock.mockResolvedValue({
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: true,
    });

    const req = { body: {}, headers: {}, get: vi.fn() } as any;
    await sendLoginEmailOTP(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(authEventLogMock).toHaveBeenCalledWith(
      expect.objectContaining({ userId: null, type: 'login_failed' }),
    );
  });

  it('returns 401 when the phone verification token is missing', async () => {
    const { verifyPhoneNumber } = await loadOtpController();
    const res = buildRes();

    await verifyPhoneNumber(buildReq(buildUser(), { body: {} }), res);

    expect(verifyPhoneOTPMock).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not Allowed.' });
  });

  it('returns 401 when the phone is missing during verification', async () => {
    const { verifyPhoneNumber } = await loadOtpController();
    const res = buildRes();

    await verifyPhoneNumber(
      buildReq(buildUser({ phone: null }), { body: { verificationToken: '123456' } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not Allowed.' });
  });

  it('returns 200 when phone verification completes the user', async () => {
    const { verifyPhoneNumber } = await loadOtpController();
    const res = buildRes();
    const verifiedUser = buildUser({ phoneVerified: true, emailVerified: true, verified: true });
    verifyPhoneOTPMock.mockResolvedValue({ user: verifiedUser, verified: true });

    await verifyPhoneNumber(buildReq(buildUser(), { body: { verificationToken: '123456' } }), res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
  });

  it('returns 401 when phone verification does not match', async () => {
    const { verifyPhoneNumber } = await loadOtpController();
    const res = buildRes();
    verifyPhoneOTPMock.mockResolvedValue({ user: buildUser(), verified: false });

    await verifyPhoneNumber(buildReq(buildUser(), { body: { verificationToken: 'wrong' } }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('returns 500 when phone verification throws', async () => {
    const { verifyPhoneNumber } = await loadOtpController();
    const res = buildRes();
    verifyPhoneOTPMock.mockRejectedValue(new Error('db down'));

    await verifyPhoneNumber(buildReq(buildUser(), { body: { verificationToken: '123456' } }), res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
  });

  it('returns 401 when the email verification token or expiry is missing', async () => {
    const { verifyEmail } = await loadOtpController();
    const res = buildRes();

    await verifyEmail(
      buildReq(buildUser({ emailVerificationTokenExpiry: null }), {
        body: { verificationToken: 'EMAILOTP' },
      }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data.' });
  });

  it('returns 401 when the email verification token is absent from the body', async () => {
    const { verifyEmail } = await loadOtpController();
    const res = buildRes();

    await verifyEmail(buildReq(buildUser(), { body: {} }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data' });
  });

  it('returns 401 when the email is missing during verification', async () => {
    const { verifyEmail } = await loadOtpController();
    const res = buildRes();

    await verifyEmail(
      buildReq(buildUser({ email: null as unknown as string }), {
        body: { verificationToken: 'EMAILOTP' },
      }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid data' });
  });

  it('returns success without a session when email verification is partial', async () => {
    const { verifyEmail } = await loadOtpController();
    const res = buildRes();
    const partialUser = buildUser({ emailVerified: true, verified: false });
    verifyEmailOTPMock.mockResolvedValue({ user: partialUser, verified: true });

    await verifyEmail(buildReq(buildUser(), { body: { verificationToken: 'EMAILOTP' } }), res);

    expect(issueSessionAndRespondMock).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
  });

  it('defaults roles to an empty array on full email verification', async () => {
    const { verifyEmail } = await loadOtpController();
    const res = buildRes();
    const verifiedUser = buildUser({ roles: undefined });
    verifyEmailOTPMock.mockResolvedValue({ user: verifiedUser, verified: true });

    await verifyEmail(buildReq(buildUser(), { body: { verificationToken: 'EMAILOTP' } }), res);

    expect(issueSessionAndRespondMock).toHaveBeenCalledWith(
      expect.objectContaining({ user: expect.objectContaining({ roles: [] }) }),
    );
  });

  it('returns 401 when email verification does not match', async () => {
    const { verifyEmail } = await loadOtpController();
    const res = buildRes();
    verifyEmailOTPMock.mockResolvedValue({ user: buildUser(), verified: false });

    await verifyEmail(buildReq(buildUser(), { body: { verificationToken: 'wrong' } }), res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('stops login phone verification when the user is locked out', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController();
    const res = buildRes();
    rejectIfUserLockedMock.mockResolvedValue(true);

    await verifyLoginPhoneNumber(
      buildReq(buildUser(), { body: { verificationToken: '123456' } }),
      res,
    );

    expect(verifyPhoneOTPMock).not.toHaveBeenCalled();
  });

  it('returns 401 when login phone verification data is missing', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController();
    const res = buildRes();

    await verifyLoginPhoneNumber(
      buildReq(buildUser({ phoneVerificationToken: undefined }), {
        body: { verificationToken: '123456' },
      }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('returns 401 when the login phone or email is missing', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController();
    const res = buildRes();

    await verifyLoginPhoneNumber(
      buildReq(buildUser({ phone: null }), { body: { verificationToken: '123456' } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not Allowed.' });
  });

  it('returns success without a session when login phone verification is partial', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController();
    const res = buildRes();
    const partialUser = buildUser({ phoneVerified: true, emailVerified: false, verified: false });
    verifyPhoneOTPMock.mockResolvedValue({ user: partialUser, verified: true });

    await verifyLoginPhoneNumber(
      buildReq(buildUser(), { body: { verificationToken: '123456' } }),
      res,
    );

    expect(issueSessionAndRespondMock).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
  });

  it('returns 500 when login phone verification throws', async () => {
    const { verifyLoginPhoneNumber } = await loadOtpController();
    const res = buildRes();
    verifyPhoneOTPMock.mockRejectedValue(new Error('db down'));

    await verifyLoginPhoneNumber(
      buildReq(buildUser(), { body: { verificationToken: '123456' } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
  });

  it('stops login email verification when the user is locked out', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const res = buildRes();
    rejectIfUserLockedMock.mockResolvedValue(true);

    await verifyLoginEmail(buildReq(buildUser(), { body: { verificationToken: 'EMAILOTP' } }), res);

    expect(verifyEmailOTPMock).not.toHaveBeenCalled();
  });

  it('returns 401 when login email verification data is missing', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const res = buildRes();

    await verifyLoginEmail(
      buildReq(buildUser({ emailVerificationToken: undefined }), {
        body: { verificationToken: 'EMAILOTP' },
      }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('defaults roles to an empty array on full login email verification', async () => {
    const { verifyLoginEmail } = await loadOtpController();
    const res = buildRes();
    const verifiedUser = buildUser({ roles: undefined });
    verifyEmailOTPMock.mockResolvedValue({ user: verifiedUser, verified: true });

    await verifyLoginEmail(buildReq(buildUser(), { body: { verificationToken: 'EMAILOTP' } }), res);

    expect(issueSessionAndRespondMock).toHaveBeenCalledWith(
      expect.objectContaining({ user: expect.objectContaining({ roles: [] }) }),
    );
  });
});
