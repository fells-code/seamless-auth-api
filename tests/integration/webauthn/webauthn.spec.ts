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

function prfSalt(byte = 1) {
  return Buffer.alloc(32, byte).toString('base64url');
}

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = buildUser();
      req.sessionId = 'session-1';
      next();
    },
  };
});

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

  it('adds PRF creation extension when requested', async () => {
    (Credential.findAll as any).mockResolvedValue([]);
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
    });

    const { generateRegistrationOptions } = await import('@simplewebauthn/server');

    (generateRegistrationOptions as any).mockResolvedValue({
      challenge: 'challenge',
    });

    const res = await request(app).get('/webauthn/register/start').query({ requirePrf: 'true' });

    expect(res.status).toBe(200);
    expect(generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        extensions: { prf: {} },
      }),
    );
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

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({
        attestationResponse: {
          clientExtensionResults: {
            prf: { enabled: true },
          },
        },
        metadata: {},
      });

    expect(res.status).toBe(200);
    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({
        prfCapable: true,
      }),
    );
  });

  it('rejects PRF-required registration when credential is not PRF-capable', async () => {
    const user = buildUser({
      challengeContext: {
        webauthnRegistration: {
          prfRequested: true,
          requirePrf: true,
        },
      },
    });

    (User.findOne as any).mockResolvedValue(user);
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

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({
        attestationResponse: {
          clientExtensionResults: {
            prf: { enabled: false },
          },
        },
        metadata: {},
      });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'prf_required' });
    expect(Credential.create).not.toHaveBeenCalled();
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
    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        extensions: undefined,
      }),
    );
  });

  it('adds PRF assertion extension and filters to PRF-capable credentials', async () => {
    (Credential.findAll as any).mockResolvedValue([
      buildCredential({ id: 'regular-cred', prfCapable: false }),
      buildCredential({ id: 'prf-cred', prfCapable: true }),
    ]);

    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');

    (generateAuthenticationOptions as any).mockResolvedValue({
      challenge: 'challenge',
    });

    const res = await request(app)
      .post('/webauthn/login/start')
      .send({ prf: { salt: prfSalt() } });

    expect(res.status).toBe(200);
    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        allowCredentials: [{ id: 'prf-cred', transports: [] }],
        extensions: {
          prf: {
            eval: {
              first: prfSalt(),
            },
          },
        },
      }),
    );
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

  it('rejects assertion responses that include PRF output', async () => {
    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({
        assertionResponse: {
          id: 'cred-1',
          clientExtensionResults: {
            prf: {
              results: {
                first: 'must-not-reach-server',
              },
            },
          },
        },
      });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'prf_output_not_allowed' });
  });
});
