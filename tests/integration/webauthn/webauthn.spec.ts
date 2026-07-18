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
import { AuthEvent } from '../../../src/models/authEvents';
import {
  generateWebAuthn,
  registerWebAuthn,
  verifyWebAuthn,
  verifyWebAuthnRegistration,
} from '../../../src/controllers/webauthn';
import { maybePromoteBootstrapAdmin } from '../../../src/services/bootstrapPromotionService';

vi.mock('../../../src/services/bootstrapPromotionService.js', () => ({
  getBootstrapInviteTokenHash: vi.fn(() => null),
  maybePromoteBootstrapAdmin: vi.fn(async () => ({ promoted: false })),
  createBootstrapInviteTokenHash: vi.fn(() => 'hash'),
  BOOTSTRAP_INVITE_TOKEN_HASH_CONTEXT_KEY: 'bootstrapInviteTokenHash',
}));

let app: Application;

function prfSalt(byte = 1) {
  return Buffer.alloc(32, byte).toString('base64url');
}

function buildRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  res.send = vi.fn().mockReturnValue(res);
  return res;
}

function buildReq(overrides: Record<string, unknown> = {}) {
  return {
    body: {},
    query: {},
    ip: '127.0.0.1',
    headers: {},
    get: () => undefined,
    ...overrides,
  } as any;
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
  (AuthEvent.count as any).mockResolvedValue(0);
  (getSystemConfig as any).mockResolvedValue({
    app_name: 'SeamlessAuth',
    rpid: 'localhost',
    origins: ['http://localhost:5137'],
    access_token_ttl: '15m',
    refresh_token_ttl: '1h',
  });
  (Credential.findAll as any).mockResolvedValue([]);
  (Credential.findOne as any).mockResolvedValue(null);
  (maybePromoteBootstrapAdmin as any).mockResolvedValue({ promoted: false });
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

  it('excludes existing credentials from the registration options', async () => {
    (Credential.findAll as any).mockResolvedValue([
      buildCredential({ id: 'cred-1', transports: ['internal'] }),
    ]);
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);
    expect(generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        excludeCredentials: [{ id: 'cred-1', transports: ['internal'] }],
      }),
    );
  });

  it('returns 500 when credential lookup fails', async () => {
    (Credential.findAll as any).mockRejectedValue(new Error('db down'));

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(500);
  });

  it('rejects when there is no verified user', async () => {
    const res = buildRes();

    await registerWebAuthn(buildReq({ user: undefined }), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'Not allowed' });
  });

  it('rejects when the verified user is missing an email', async () => {
    const res = buildRes();

    await registerWebAuthn(buildReq({ user: { id: 'user-1', email: null } }), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'Not allowed' });
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

  it('rejects verification for an unknown user record', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(403);
  });

  it('rejects verification when the stored challenge is missing', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ challenge: null }));

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(403);
  });

  it('returns 500 when the attestation verification throws', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockRejectedValue(new Error('bad attestation'));

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(500);
  });

  it('rejects when the attestation is not verified', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockResolvedValue({ verified: false });

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(403);
  });

  it('returns 500 when persisting the credential fails', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    (Credential.create as any).mockRejectedValue(new Error('write failed'));
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Unknown error verifying passkey' });
  });

  it('rejects when the verified user is missing an email', async () => {
    const res = buildRes();

    await verifyWebAuthnRegistration(
      buildReq({ user: { id: 'user-1', email: null }, body: { attestationResponse: {} } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'Not allowed' });
  });

  it('rejects when there is no verified user', async () => {
    const res = buildRes();

    await verifyWebAuthnRegistration(
      buildReq({ user: undefined, body: { attestationResponse: {} } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'Not allowed' });
  });

  it('completes registration when the user is promoted to bootstrap admin', async () => {
    const user = buildUser({ roles: undefined });
    (User.findOne as any).mockResolvedValue(user);
    (maybePromoteBootstrapAdmin as any).mockResolvedValue({ promoted: true });
    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (signAccessToken as any).mockResolvedValue('access-token');
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(200);
    expect(maybePromoteBootstrapAdmin).toHaveBeenCalledWith(
      expect.objectContaining({ completionMethod: 'webauthn_registration' }),
    );
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

  it('filters allowed credentials by the requested credential id', async () => {
    (Credential.findAll as any).mockResolvedValue([
      buildCredential({ id: 'cred-1' }),
      buildCredential({ id: 'cred-2' }),
    ]);
    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');
    (generateAuthenticationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app).post('/webauthn/login/start').send({ credentialId: 'cred-1' });

    expect(res.status).toBe(200);
    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        allowCredentials: [{ id: 'cred-1', transports: [] }],
      }),
    );
  });

  it('rejects login start when no PRF-capable credential is available', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential({ prfCapable: false })]);

    const res = await request(app)
      .post('/webauthn/login/start')
      .send({ prf: { salt: prfSalt() } });

    expect(res.status).toBe(401);
  });

  it('returns 500 when generating options fails', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential()]);
    (getSystemConfig as any).mockRejectedValue(new Error('config down'));

    const res = await request(app).post('/webauthn/login/start');

    expect(res.status).toBe(500);
  });

  it('rejects when the pre-authenticated user has no identifier', async () => {
    const res = buildRes();

    await generateWebAuthn(
      buildReq({ user: { id: 'user-1', email: null, phone: null }, body: undefined }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'Not allowed' });
  });

  it('rejects when the user has no stored credentials', async () => {
    (Credential.findAll as any).mockResolvedValue(null);

    const res = await request(app).post('/webauthn/login/start');

    expect(res.status).toBe(401);
  });

  it('returns 500 when option generation rejects with a non-error', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential()]);
    (getSystemConfig as any).mockRejectedValue('config down');

    const res = await request(app).post('/webauthn/login/start');

    expect(res.status).toBe(500);
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

  it('returns 423 when the account is locked', async () => {
    (AuthEvent.count as any).mockResolvedValue(10);
    (getSystemConfig as any).mockResolvedValue({
      lockout_policy: {
        enabled: true,
        maxFailures: 10,
        windowSeconds: 900,
        lockoutSeconds: 900,
      },
    });

    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'cred-1' } });

    expect(res.status).toBe(423);
    expect(res.body.error).toBe('account_locked');
  });

  it('returns 500 when the assertion verification throws', async () => {
    const user = buildUser({ challenge: 'challenge' });
    (User.findOne as any).mockResolvedValue(user);
    (Credential.findOne as any).mockResolvedValue(buildCredential({ id: 'cred-1' }));
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5137'],
      rpid: 'localhost',
    });
    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockRejectedValue(new Error('bad assertion'));

    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'cred-1' } });

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Internal server error' });
  });

  it('returns 500 when the credential lookup throws', async () => {
    (Credential.findOne as any).mockRejectedValue(new Error('db down'));

    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'cred-1' } });

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Internal Server error' });
  });

  it('rejects when the pre-authenticated user has no identifier', async () => {
    const res = buildRes();

    await verifyWebAuthn(
      buildReq({
        user: { id: 'user-1', email: null, phone: null, challenge: 'challenge' },
        body: { assertionResponse: { id: 'cred-1' } },
      }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'Not allowed' });
  });

  it('rejects when the user challenge is missing', async () => {
    const res = buildRes();

    await verifyWebAuthn(
      buildReq({
        user: { id: 'user-1', email: 'test@example.com', phone: null, challenge: null },
        body: { assertionResponse: { id: 'cred-1' } },
      }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Authentication failed.' });
  });

  it('sends no response when the assertion is not verified', async () => {
    (Credential.findOne as any).mockResolvedValue(buildCredential({ id: 'cred-1' }));
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5137'],
      rpid: 'localhost',
    });
    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockResolvedValue({
      verified: false,
      authenticationInfo: { newCounter: 1 },
    });

    const res = buildRes();
    const credential = buildCredential({ id: 'cred-1' });
    (Credential.findOne as any).mockResolvedValue(credential);

    await verifyWebAuthn(
      buildReq({
        user: {
          id: 'user-1',
          email: 'test@example.com',
          phone: null,
          challenge: 'challenge',
          update: vi.fn(),
        },
        body: { assertionResponse: { id: 'cred-1' } },
      }),
      res,
    );

    expect(credential.update).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
    expect(res.send).not.toHaveBeenCalled();
  });

  it('issues a session on a verified assertion even when roles are absent', async () => {
    const credential = buildCredential({ id: 'cred-1' });
    (Credential.findOne as any).mockResolvedValue(credential);
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (signAccessToken as any).mockResolvedValue('access-token');
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 3 },
    });

    const res = buildRes();

    await verifyWebAuthn(
      buildReq({
        user: {
          id: 'user-1',
          email: 'test@example.com',
          phone: null,
          roles: undefined,
          challenge: 'challenge',
          update: vi.fn(),
        },
        body: { assertionResponse: { id: 'cred-1' } },
      }),
      res,
    );

    expect(credential.update).toHaveBeenCalledWith(expect.objectContaining({ counter: 3 }));
    expect(res.status).toHaveBeenCalledWith(200);
  });
});
