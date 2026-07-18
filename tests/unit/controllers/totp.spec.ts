import { beforeEach, describe, expect, it, vi } from 'vitest';

const getTotpStatusMock = vi.fn();
const startTotpEnrollmentMock = vi.fn();
const verifyTotpEnrollmentMock = vi.fn();
const disableTotpMock = vi.fn();
const verifyEnabledTotpMock = vi.fn();
const authEventLogMock = vi.fn();
const rejectIfUserLockedMock = vi.fn();
const issueSessionAndRespondMock = vi.fn();
const recordStepUpVerificationMock = vi.fn();
const serializeStepUpStatusMock = vi.fn();
const getSystemConfigMock = vi.fn();
const loggerMock = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

vi.mock('../../../src/services/totpService.js', () => ({
  disableTotp: disableTotpMock,
  getTotpStatus: getTotpStatusMock,
  startTotpEnrollment: startTotpEnrollmentMock,
  verifyEnabledTotp: verifyEnabledTotpMock,
  verifyTotpEnrollment: verifyTotpEnrollmentMock,
}));

vi.mock('../../../src/services/authEventService.js', () => ({
  AuthEventService: {
    log: authEventLogMock,
  },
}));

vi.mock('../../../src/services/lockoutPolicyService.js', () => ({
  rejectIfUserLocked: rejectIfUserLockedMock,
}));

vi.mock('../../../src/services/sessionIssuance.js', () => ({
  issueSessionAndRespond: issueSessionAndRespondMock,
}));

vi.mock('../../../src/services/stepUpService.js', () => ({
  recordStepUpVerification: recordStepUpVerificationMock,
  serializeStepUpStatus: serializeStepUpStatusMock,
}));

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: getSystemConfigMock,
}));

vi.mock('../../../src/utils/logger.js', () => ({
  default: () => loggerMock,
}));

type MockUser = {
  id?: string;
  email?: string | null;
  phone?: string | null;
  roles?: string[];
  update: ReturnType<typeof vi.fn>;
};

function buildUser(overrides: Partial<MockUser> = {}): MockUser {
  return {
    id: 'user-1',
    email: 'test@example.com',
    phone: '+14155552671',
    roles: ['user'],
    update: vi.fn(),
    ...overrides,
  };
}

function buildReq(user: MockUser | undefined, overrides: Record<string, unknown> = {}) {
  return {
    body: {},
    headers: {},
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

async function loadTotpController() {
  vi.resetModules();
  return import('../../../src/controllers/totp.js');
}

beforeEach(() => {
  vi.clearAllMocks();
  rejectIfUserLockedMock.mockResolvedValue(false);
  getSystemConfigMock.mockResolvedValue({ app_name: 'Seamless Auth' });
});

describe('totp controller', () => {
  describe('getCurrentTotpStatus', () => {
    it('returns 401 when the user is missing an id', async () => {
      const { getCurrentTotpStatus } = await loadTotpController();
      const res = buildRes();

      await getCurrentTotpStatus(buildReq(buildUser({ id: undefined })), res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
      expect(getTotpStatusMock).not.toHaveBeenCalled();
    });

    it('serializes status dates, mapping null values to null', async () => {
      const { getCurrentTotpStatus } = await loadTotpController();
      const res = buildRes();
      getTotpStatusMock.mockResolvedValue({
        enabled: true,
        verifiedAt: new Date('2026-05-16T12:00:00.000Z'),
        lastUsedAt: null,
      });

      await getCurrentTotpStatus(buildReq(buildUser()), res);

      expect(getTotpStatusMock).toHaveBeenCalledWith('user-1');
      expect(res.json).toHaveBeenCalledWith({
        enabled: true,
        verifiedAt: '2026-05-16T12:00:00.000Z',
        lastUsedAt: null,
      });
    });
  });

  describe('startCurrentTotpEnrollment', () => {
    it('returns 401 and logs suspicion when the user has no email', async () => {
      const { startCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();

      await startCurrentTotpEnrollment(buildReq(buildUser({ email: null })), res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'totp_suspicious' }),
      );
      expect(startTotpEnrollmentMock).not.toHaveBeenCalled();
    });

    it('logs a null userId when the user has no id', async () => {
      const { startCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();

      await startCurrentTotpEnrollment(buildReq(buildUser({ id: undefined })), res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: null, type: 'totp_suspicious' }),
      );
    });

    it('starts enrollment using the configured issuer', async () => {
      const { startCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();
      getSystemConfigMock.mockResolvedValue({ app_name: 'MyApp' });
      startTotpEnrollmentMock.mockResolvedValue({ secret: 'ABC', otpauthUrl: 'otpauth://totp/x' });

      await startCurrentTotpEnrollment(buildReq(buildUser()), res);

      expect(startTotpEnrollmentMock).toHaveBeenCalledWith({
        userId: 'user-1',
        email: 'test@example.com',
        issuer: 'MyApp',
      });
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        message: 'Success',
        secret: 'ABC',
        otpauthUrl: 'otpauth://totp/x',
      });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'totp_enrollment_started' }),
      );
    });

    it('falls back to the default issuer when app_name is unset', async () => {
      const { startCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();
      getSystemConfigMock.mockResolvedValue({});
      startTotpEnrollmentMock.mockResolvedValue({ secret: 'ABC', otpauthUrl: 'otpauth://totp/x' });

      await startCurrentTotpEnrollment(buildReq(buildUser()), res);

      expect(startTotpEnrollmentMock).toHaveBeenCalledWith(
        expect.objectContaining({ issuer: 'Seamless Auth' }),
      );
    });

    it('returns 500 and logs failure when enrollment throws', async () => {
      const { startCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();
      startTotpEnrollmentMock.mockRejectedValue(new Error('boom'));

      await startCurrentTotpEnrollment(buildReq(buildUser()), res);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'totp_failed' }),
      );
    });
  });

  describe('verifyCurrentTotpEnrollment', () => {
    it('returns 401 when the user is missing an id', async () => {
      const { verifyCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();

      await verifyCurrentTotpEnrollment(
        buildReq(buildUser({ id: undefined }), { body: { code: '123456' } }),
        res,
      );

      expect(res.status).toHaveBeenCalledWith(401);
      expect(verifyTotpEnrollmentMock).not.toHaveBeenCalled();
    });

    it('returns 401 and logs failure when verification fails', async () => {
      const { verifyCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();
      verifyTotpEnrollmentMock.mockResolvedValue({ verified: false, reason: 'bad_code' });

      await verifyCurrentTotpEnrollment(buildReq(buildUser(), { body: { code: '000000' } }), res);

      expect(verifyTotpEnrollmentMock).toHaveBeenCalledWith('user-1', '000000');
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'totp_verification_failed' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-1',
          type: 'totp_failed',
          metadata: { reason: 'bad_code' },
        }),
      );
    });

    it('confirms enrollment and logs success', async () => {
      const { verifyCurrentTotpEnrollment } = await loadTotpController();
      const res = buildRes();
      verifyTotpEnrollmentMock.mockResolvedValue({ verified: true });

      await verifyCurrentTotpEnrollment(buildReq(buildUser(), { body: { code: '123456' } }), res);

      expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'totp_enrollment_success' }),
      );
    });
  });

  describe('disableCurrentTotp', () => {
    it('returns 401 when the user is missing an id', async () => {
      const { disableCurrentTotp } = await loadTotpController();
      const res = buildRes();

      await disableCurrentTotp(
        buildReq(buildUser({ id: undefined }), { body: { code: '123456' } }),
        res,
      );

      expect(res.status).toHaveBeenCalledWith(401);
      expect(disableTotpMock).not.toHaveBeenCalled();
    });

    it('returns 401 and logs failure when disable fails', async () => {
      const { disableCurrentTotp } = await loadTotpController();
      const res = buildRes();
      disableTotpMock.mockResolvedValue({ disabled: false, reason: 'bad_code' });

      await disableCurrentTotp(buildReq(buildUser(), { body: { code: '000000' } }), res);

      expect(disableTotpMock).toHaveBeenCalledWith('user-1', '000000');
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'totp_disable_failed' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'totp_failed' }),
      );
    });

    it('disables TOTP and logs success', async () => {
      const { disableCurrentTotp } = await loadTotpController();
      const res = buildRes();
      disableTotpMock.mockResolvedValue({ disabled: true });

      await disableCurrentTotp(buildReq(buildUser(), { body: { code: '123456' } }), res);

      expect(res.json).toHaveBeenCalledWith({ message: 'Success' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'totp_disabled' }),
      );
    });
  });

  describe('verifyTotpLogin', () => {
    it('returns 401 and logs suspicion when no pre-authenticated user', async () => {
      const { verifyTotpLogin } = await loadTotpController();
      const res = buildRes();

      await verifyTotpLogin(
        buildReq(buildUser({ id: undefined }), { body: { code: '123456' } }),
        res,
      );

      expect(res.status).toHaveBeenCalledWith(401);
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: null, type: 'totp_suspicious' }),
      );
      expect(verifyEnabledTotpMock).not.toHaveBeenCalled();
    });

    it('stops when the user is locked out', async () => {
      const { verifyTotpLogin } = await loadTotpController();
      const res = buildRes();
      rejectIfUserLockedMock.mockResolvedValue(true);

      await verifyTotpLogin(buildReq(buildUser(), { body: { code: '123456' } }), res);

      expect(verifyEnabledTotpMock).not.toHaveBeenCalled();
      expect(issueSessionAndRespondMock).not.toHaveBeenCalled();
    });

    it('returns 401 and logs failure when the code is invalid', async () => {
      const { verifyTotpLogin } = await loadTotpController();
      const res = buildRes();
      verifyEnabledTotpMock.mockResolvedValue({ verified: false, reason: 'bad_code' });

      await verifyTotpLogin(buildReq(buildUser(), { body: { code: '000000' } }), res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'totp_verification_failed' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-1',
          type: 'totp_failed',
          metadata: { reason: 'bad_code', flow: 'login' },
        }),
      );
    });

    it('issues a session and records last login on success', async () => {
      const { verifyTotpLogin } = await loadTotpController();
      const res = buildRes();
      const user = buildUser();
      verifyEnabledTotpMock.mockResolvedValue({ verified: true });

      const req = buildReq(user, { body: { code: '123456' } });
      await verifyTotpLogin(req, res);

      expect(issueSessionAndRespondMock).toHaveBeenCalledWith({
        user: {
          id: 'user-1',
          email: 'test@example.com',
          phone: '+14155552671',
          roles: ['user'],
        },
        req,
        res,
      });
      expect(user.update).toHaveBeenCalledWith({ lastLogin: expect.any(Date) });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'totp_success' }),
      );
    });

    it('defaults roles to an empty array when the user has none', async () => {
      const { verifyTotpLogin } = await loadTotpController();
      const res = buildRes();
      const user = buildUser({ roles: undefined });
      verifyEnabledTotpMock.mockResolvedValue({ verified: true });

      await verifyTotpLogin(buildReq(user, { body: { code: '123456' } }), res);

      expect(issueSessionAndRespondMock).toHaveBeenCalledWith(
        expect.objectContaining({ user: expect.objectContaining({ roles: [] }) }),
      );
    });
  });

  describe('verifyTotpMfa', () => {
    it('returns 401 when the session context is missing', async () => {
      const { verifyTotpMfa } = await loadTotpController();
      const res = buildRes();

      await verifyTotpMfa(buildReq(buildUser(), { body: { code: '123456' } }), res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(verifyEnabledTotpMock).not.toHaveBeenCalled();
    });

    it('returns 401 and logs failure when the code is invalid', async () => {
      const { verifyTotpMfa } = await loadTotpController();
      const res = buildRes();
      verifyEnabledTotpMock.mockResolvedValue({ verified: false, reason: 'bad_code' });

      await verifyTotpMfa(
        buildReq(buildUser(), { body: { code: '000000' }, sessionId: 'session-1' }),
        res,
      );

      expect(res.status).toHaveBeenCalledWith(401);
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-1',
          type: 'mfa_otp_failed',
          metadata: { reason: 'bad_code', method: 'totp' },
        }),
      );
    });

    it('returns 401 when the step-up record cannot be persisted', async () => {
      const { verifyTotpMfa } = await loadTotpController();
      const res = buildRes();
      verifyEnabledTotpMock.mockResolvedValue({ verified: true });
      recordStepUpVerificationMock.mockResolvedValue(null);

      await verifyTotpMfa(
        buildReq(buildUser(), { body: { code: '123456' }, sessionId: 'session-1' }),
        res,
      );

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
    });

    it('records step-up freshness and returns success', async () => {
      const { verifyTotpMfa } = await loadTotpController();
      const res = buildRes();
      verifyEnabledTotpMock.mockResolvedValue({ verified: true });
      recordStepUpVerificationMock.mockResolvedValue({ stepUpVerifiedAt: new Date() });
      serializeStepUpStatusMock.mockReturnValue({ fresh: true });

      await verifyTotpMfa(
        buildReq(buildUser(), { body: { code: '123456' }, sessionId: 'session-1' }),
        res,
      );

      expect(recordStepUpVerificationMock).toHaveBeenCalledWith({
        sessionId: 'session-1',
        userId: 'user-1',
        method: 'totp',
      });
      expect(res.json).toHaveBeenCalledWith({ message: 'Success', fresh: true, method: 'totp' });
      expect(authEventLogMock).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-1', type: 'mfa_otp_success' }),
      );
    });
  });
});
