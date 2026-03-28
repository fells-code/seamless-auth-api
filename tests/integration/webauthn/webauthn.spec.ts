import request from 'supertest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { Application } from 'express';
import { Credential } from '../../../src/models/credentials';
import { attachAuthMiddleware } from '../../../src/middleware/attachAuthMiddleware';
import { createApp } from '../../../src/app';
import { buildSystemConfig } from '../../factories/systemConfigFactory';
import { Session } from '../../../src/models/sessions';
import { User } from '../../../src/models/users';
import { buildUser } from '../../factories/userFactory';
import { buildCredential } from '../../factories/credentialFactory';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../../../src/lib/token';

let app: Application;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', () => ({
  attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
    req.user = buildUser();
    req.sessionId = 'session-1';
    next();
  },
}));

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('GET /webauthn/register/start', () => {
  it('returns challenge', async () => {
    (Credential.findAll as any).mockResolvedValue([]);
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
    });

    const { generateRegistrationOptions } = await import('@simplewebauthn/server');

    (generateRegistrationOptions as any).mockResolvedValue({
      challenge: 'challenge',
    });

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);
    expect(res.body.challenge).toBeDefined();
  });
});

describe('POST /webauthn/register/finish', () => {
  it('creates credential and session', async () => {
    const user = buildUser();

    (signAccessToken as any).mockResolvedValue('access-token');
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
    (User.findOne as any).mockResolvedValue(user);
    (Credential.findAll as any).mockResolvedValue([buildCredential({ id: 'cred-1' })]);
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: {
          id: 'cred-1',
          publicKey: Buffer.from('key'),
          counter: 0,
          transports: [],
        },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    const res = await request(app).post('/webauthn/register/finish').send({
      attestationResponse: {},
      metadata: {},
    });

    expect(res.status).toBe(200);
  });
});

describe('POST /webauthn/login/start', () => {
  it('rejects when no credentials', async () => {
    (Credential.findAll as any).mockResolvedValue([]);

    const res = await request(app).post('/webauthn/login/start');

    expect(res.status).toBe(401);
  });

  it('returns challenge', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential()]);

    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');

    (generateAuthenticationOptions as any).mockResolvedValue({
      challenge: 'challenge',
    });

    const res = await request(app).post('/webauthn/login/start');

    expect(res.status).toBe(200);
    expect(res.body.challenge).toBeDefined();
  });
});

describe('POST /webauthn/login/finish', () => {
  it('rejects missing credential', async () => {
    (Credential.findOne as any).mockResolvedValue(null);

    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'bad' } });

    expect(res.status).toBe(401);
  });

  it('logs in successfully', async () => {
    const user = buildUser({ challenge: 'challenge' });
    const { attachAuthMiddleware } = await import('../../../src/middleware/attachAuthMiddleware');
    (Credential.findOne as any).mockResolvedValue(
      buildCredential({ id: 'cred-1', userId: user.id }),
    );
    (signAccessToken as any).mockResolvedValue('access-token');
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
    (User.findOne as any).mockResolvedValue(user);
    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');

    (verifyAuthenticationResponse as any).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
      id: 'cred-1',
    });

    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({
        assertionResponse: { id: 'cred-1' },
      });

    expect(res.status).toBe(200);
  });
});
