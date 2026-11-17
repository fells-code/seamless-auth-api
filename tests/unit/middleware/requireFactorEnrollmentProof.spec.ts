import { beforeEach, describe, expect, it, vi } from 'vitest';

import { requireFactorEnrollmentProof } from '../../../src/middleware/requireFactorEnrollmentProof';
import { Credential } from '../../../src/models/credentials';
import { Session } from '../../../src/models/sessions';
import { TotpCredential } from '../../../src/models/totpCredentials';
import { buildSession } from '../../factories/sessionFactory';

const MINUTE_MS = 60_000;

function buildReq(overrides: Record<string, unknown> = {}) {
  return { user: { id: 'user-1' }, sessionId: 'session-1', ...overrides } as never;
}

describe('requireFactorEnrollmentProof', () => {
  let res: any;
  let next: any;

  beforeEach(() => {
    vi.clearAllMocks();
    res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    next = vi.fn();
    (Credential.count as any).mockResolvedValue(0);
    (TotpCredential.count as any).mockResolvedValue(0);
  });

  function withSession(overrides: Record<string, unknown> = {}) {
    (Session.findOne as any).mockResolvedValue(buildSession(overrides));
  }

  it('documents the 403 it can answer', () => {
    expect(requireFactorEnrollmentProof.seamlessDeviceStepUp).toBe(true);
  });

  it('refuses a session from a device grant with no step-up', async () => {
    await requireFactorEnrollmentProof(
      buildReq({ deviceChildSession: { stepUpVerifiedAt: null, stepUpMethod: null } }),
      res,
      next,
    );

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'step_up_required' }));
  });

  it('lets a recovery session enrol', async () => {
    await requireFactorEnrollmentProof(buildReq({ recoverySession: true }), res, next);

    expect(next).toHaveBeenCalled();
    expect(Session.findOne).not.toHaveBeenCalled();
  });

  it('refuses when the session is gone', async () => {
    (Session.findOne as any).mockResolvedValue(null);

    await requireFactorEnrollmentProof(buildReq(), res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('refuses a request with no user or session id', async () => {
    await requireFactorEnrollmentProof(buildReq({ user: undefined }), res, next);
    await requireFactorEnrollmentProof(buildReq({ sessionId: undefined }), res, next);

    expect(res.status).toHaveBeenCalledTimes(2);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(Session.findOne).not.toHaveBeenCalled();
  });

  describe('an account that already has a factor', () => {
    it('needs a fresh step-up even right after signing in', async () => {
      (Credential.count as any).mockResolvedValue(1);
      withSession({ authTime: new Date(), stepUpVerifiedAt: null });

      await requireFactorEnrollmentProof(buildReq(), res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'step_up_required', fresh: false }),
      );
    });

    it('counts only an enabled TOTP as a factor', async () => {
      (TotpCredential.count as any).mockResolvedValue(1);
      withSession({ stepUpVerifiedAt: new Date(Date.now() - 6 * MINUTE_MS) });

      await requireFactorEnrollmentProof(buildReq(), res, next);

      expect(TotpCredential.count).toHaveBeenCalledWith({
        where: { userId: 'user-1', enabled: true },
      });
      expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'step_up_required' }));
    });

    it('passes a fresh step-up', async () => {
      (Credential.count as any).mockResolvedValue(2);
      withSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' });

      await requireFactorEnrollmentProof(buildReq(), res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('an account with no factor', () => {
    it('passes a recent sign-in', async () => {
      withSession({ authTime: new Date(Date.now() - 9 * MINUTE_MS) });

      await requireFactorEnrollmentProof(buildReq(), res, next);

      expect(next).toHaveBeenCalled();
    });

    it('asks for a new sign-in once the sign-in is old', async () => {
      withSession({ authTime: new Date(Date.now() - 11 * MINUTE_MS) });

      await requireFactorEnrollmentProof(buildReq(), res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        error: 'reauthentication_required',
        message: 'Sign in again to add a sign-in method',
        maxAgeSeconds: 600,
      });
    });

    it('asks for a new sign-in when the session carries no sign-in time', async () => {
      withSession({ authTime: null });

      await requireFactorEnrollmentProof(buildReq(), res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'reauthentication_required' }),
      );
    });
  });
});
