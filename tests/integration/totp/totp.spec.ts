import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const issueSessionAndRespondMock = vi.fn(async ({ res }) => {
  res.status(200).json({ message: 'Success' });
});

vi.mock('../../../src/services/sessionIssuance.js', () => ({
  issueSessionAndRespond: issueSessionAndRespondMock,
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { createApp } from '../../../src/app.js';
import { Session } from '../../../src/models/sessions.js';
import { TotpCredential } from '../../../src/models/totpCredentials.js';
import { encryptTotpSecret } from '../../../src/services/totpService.js';
import { generateTotpCode } from '../../../src/utils/totp.js';
import { buildSession } from '../../factories/sessionFactory.js';
import { buildTotpCredential } from '../../factories/totpCredentialFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  process.env.TOTP_SECRET_ENCRYPTION_KEY = 'test-totp-encryption-key';
});

describe('TOTP routes', () => {
  it('starts TOTP enrollment with setup material', async () => {
    (getSystemConfig as any).mockResolvedValue({ app_name: 'Seamless Auth' });

    const res = await request(app).post('/totp/enroll/start');

    expect(res.status).toBe(200);
    expect(res.body.secret).toMatch(/^[A-Z2-7]+$/);
    expect(res.body.otpauthUrl).toContain('otpauth://totp/');
    expect(TotpCredential.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        enabled: false,
      }),
    );
  });

  it('returns TOTP status without exposing the secret', async () => {
    (TotpCredential.findOne as any).mockResolvedValue(
      buildTotpCredential({
        verifiedAt: new Date('2026-05-16T12:00:00.000Z'),
        lastUsedAt: new Date('2026-05-16T12:30:00.000Z'),
      }),
    );

    const res = await request(app).get('/totp/status');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      enabled: true,
      verifiedAt: '2026-05-16T12:00:00.000Z',
      lastUsedAt: '2026-05-16T12:30:00.000Z',
    });
    expect(JSON.stringify(res.body)).not.toContain('secret');
  });

  it('verifies TOTP during login and issues a session', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const code = generateTotpCode({ secret });
    (TotpCredential.findOne as any).mockResolvedValue(
      buildTotpCredential({
        ...encryptTotpSecret(secret),
        lastUsedCounter: null,
      }),
    );

    const res = await request(app).post('/totp/verify-login').send({ code });

    expect(res.status).toBe(200);
    expect(issueSessionAndRespondMock).toHaveBeenCalledWith(
      expect.objectContaining({
        user: expect.objectContaining({ id: 'user-1' }),
        clearExistingCookies: true,
      }),
    );
  });

  it('verifies TOTP as MFA and records step-up freshness', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const code = generateTotpCode({ secret });
    const session = buildSession({ stepUpVerifiedAt: null, stepUpMethod: null });

    (TotpCredential.findOne as any).mockResolvedValue(
      buildTotpCredential({
        ...encryptTotpSecret(secret),
        lastUsedCounter: null,
      }),
    );
    (Session.findOne as any).mockResolvedValue(session);

    const res = await request(app).post('/totp/verify-mfa').send({ code });

    expect(res.status).toBe(200);
    expect(res.body).toEqual(
      expect.objectContaining({
        message: 'Success',
        fresh: true,
        method: 'totp',
      }),
    );
    expect(session.stepUpMethod).toBe('totp');
    expect(session.save).toHaveBeenCalled();
  });
});
