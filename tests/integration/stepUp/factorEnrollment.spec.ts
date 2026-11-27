import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';
import { Session } from '../../../src/models/sessions.js';
import { TotpCredential } from '../../../src/models/totpCredentials.js';
import { encryptTotpSecret } from '../../../src/services/totpService.js';
import { generateTotpCode } from '../../../src/utils/totp.js';
import { buildCredential } from '../../factories/credentialFactory.js';
import { buildSession } from '../../factories/sessionFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';
import { buildTotpCredential } from '../../factories/totpCredentialFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  process.env.TOTP_SECRET_ENCRYPTION_KEY = 'test-totp-encryption-key';
  (getSystemConfig as any).mockResolvedValue(buildSystemConfig());
  (Credential.count as any).mockResolvedValue(0);
  (TotpCredential.count as any).mockResolvedValue(0);
});

const enrollmentRoutes: Array<[string, (agent: request.Agent) => request.Test]> = [
  ['POST /totp/enroll/start', (agent) => agent.post('/totp/enroll/start')],
  [
    'POST /totp/enroll/verify',
    (agent) => agent.post('/totp/enroll/verify').send({ code: '123456' }),
  ],
  ['GET /webauthn/register/start', (agent) => agent.get('/webauthn/register/start')],
  ['POST /webauthn/register/finish', (agent) => agent.post('/webauthn/register/finish').send({})],
  [
    'POST /registration/phone',
    (agent) => agent.post('/registration/phone').send({ phone: '+14155552671' }),
  ],
  [
    'POST /registration/phone/verify',
    (agent) => agent.post('/registration/phone/verify').send({ verificationToken: '123456' }),
  ],
  ['POST /recovery-codes', (agent) => agent.post('/recovery-codes')],
];

describe('adding a sign-in factor', () => {
  it.each(enrollmentRoutes)(
    '%s needs a fresh step-up on an account that has a factor',
    async (_name, send) => {
      (Credential.count as any).mockResolvedValue(1);
      (Session.findOne as any).mockResolvedValue(buildSession({ stepUpVerifiedAt: null }));

      const res = await send(request.agent(app));

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('step_up_required');
    },
  );

  it.each(enrollmentRoutes)(
    '%s needs a recent sign-in on an account with no factor',
    async (_name, send) => {
      (Session.findOne as any).mockResolvedValue(
        buildSession({ authTime: new Date(Date.now() - 60 * 60 * 1000) }),
      );

      const res = await send(request.agent(app));

      expect(res.status).toBe(403);
      expect(res.body).toEqual(
        expect.objectContaining({ error: 'reauthentication_required', maxAgeSeconds: 300 }),
      );
    },
  );
});

describe('a factor added in the current session', () => {
  it('cannot satisfy a TOTP step-up', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const session = buildSession({ stepUpVerifiedAt: null });
    (Session.findOne as any).mockResolvedValue(session);
    (TotpCredential.findOne as any).mockResolvedValue(
      buildTotpCredential({ ...encryptTotpSecret(secret), verifiedAt: new Date() }),
    );

    const res = await request(app)
      .post('/totp/verify-mfa')
      .send({ code: generateTotpCode({ secret }) });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'step_up_unavailable' });
    expect(TotpCredential.update).not.toHaveBeenCalled();
    expect(session.save).not.toHaveBeenCalled();
  });

  it('cannot satisfy a passkey step-up', async () => {
    (Session.findOne as any).mockResolvedValue(buildSession());
    (Credential.findAll as any).mockResolvedValue([buildCredential({ createdAt: new Date() })]);

    const res = await request(app).post('/step-up/webauthn/start').send({});

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'step_up_unavailable' });
  });
});

describe('DELETE /users/credentials', () => {
  it('needs a fresh step-up', async () => {
    (Session.findOne as any).mockResolvedValue(buildSession({ stepUpVerifiedAt: null }));

    const res = await request(app).delete('/users/credentials').send({ id: 'cred-1' });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('step_up_required');
    expect(Credential.findOne).not.toHaveBeenCalled();
  });
});
