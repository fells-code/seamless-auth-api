import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const issueSessionAndRespondMock = vi.fn(async ({ res }) => {
  res.status(200).json({ message: 'Success', recovery: true, nextStep: 'enroll_passkey' });
});

vi.mock('../../../src/services/sessionIssuance.js', () => ({
  issueSessionAndRespond: issueSessionAndRespondMock,
}));

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { RecoveryCode } from '../../../src/models/recoveryCodes.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { sendNoticeEmail, sendNoticeSms } from '../../../src/services/messagingService.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  process.env.REFRESH_TOKEN_LOOKUP_SECRET = 'lookup-secret';
  (getSystemConfig as any).mockResolvedValue(buildSystemConfig());
});

function withExistingSet() {
  (RecoveryCode.findAll as any).mockResolvedValue([
    { usedAt: null, createdAt: new Date('2026-10-22T00:00:00Z') },
  ]);
}

describe('GET /recovery-codes', () => {
  it('reports the set', async () => {
    withExistingSet();

    const res = await request(app).get('/recovery-codes');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      enabled: true,
      remaining: 1,
      total: 1,
      createdAt: '2026-10-22T00:00:00.000Z',
    });
  });
});

describe('POST /recovery-codes', () => {
  it('makes a first set without step-up and returns it once', async () => {
    const res = await request(app).post('/recovery-codes');

    expect(res.status).toBe(201);
    expect(res.body.codes).toHaveLength(10);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'recovery_codes_generated' }),
    );
  });

  it('needs a fresh step-up to replace an existing set', async () => {
    withExistingSet();
    (Session.findOne as any).mockResolvedValue({ id: 'session-1', stepUpVerifiedAt: null });

    const res = await request(app).post('/recovery-codes');

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('step_up_required');
    expect(RecoveryCode.bulkCreate).not.toHaveBeenCalled();
  });

  it('is refused while recovery codes are disabled', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ recovery_codes: { enabled: false, requireAtEnrollment: false } }),
    );

    const res = await request(app).post('/recovery-codes');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'recovery_codes_disabled' });
  });
});

describe('POST /recovery-codes/redeem', () => {
  it('spends the code and issues a restricted recovery session', async () => {
    const res = await request(app).post('/recovery-codes/redeem').send({ code: 'ABCDE-FGH23' });

    expect(res.status).toBe(200);
    expect(issueSessionAndRespondMock).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'recovery_code', recovery: true }),
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'recovery_code_used' }),
    );
  });

  it('tells the verified addresses that a code was used', async () => {
    await request(app).post('/recovery-codes/redeem').send({ code: 'ABCDE-FGH23' });

    // The shared test principal has both addresses verified.
    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'test@example.com',
      expect.stringContaining('recovery code was used'),
      expect.any(String),
    );
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', expect.any(String));
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'recovery_code_used',
        metadata: expect.objectContaining({
          notices: [
            { channel: 'email', status: 'sent' },
            { channel: 'phone', status: 'sent' },
          ],
        }),
      }),
    );
  });

  it('refuses a wrong or used code without issuing a session', async () => {
    (RecoveryCode.update as any).mockResolvedValueOnce([0]);

    const res = await request(app).post('/recovery-codes/redeem').send({ code: 'ABCDE-FGH23' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_recovery_code' });
    expect(issueSessionAndRespondMock).not.toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'recovery_code_failed' }),
    );
  });

  it('refuses a malformed code at validation', async () => {
    const res = await request(app).post('/recovery-codes/redeem').send({ code: '123456' });

    expect(res.status).toBe(400);
  });

  it('is refused while recovery codes are disabled', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ recovery_codes: { enabled: false, requireAtEnrollment: false } }),
    );

    const res = await request(app).post('/recovery-codes/redeem').send({ code: 'ABCDE-FGH23' });

    expect(res.status).toBe(403);
  });
});
