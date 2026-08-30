import { isoCBOR } from '@simplewebauthn/server/helpers';
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
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory';
import { buildCredential } from '../../factories/credentialFactory';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../../../src/lib/token';
import { AuthEvent } from '../../../src/models/authEvents';
import { AuthEventService } from '../../../src/services/authEventService';
import {
  generateWebAuthn,
  registerWebAuthn,
  verifyWebAuthn,
  verifyWebAuthnRegistration,
} from '../../../src/controllers/webauthn';

let app: Application;

// Packed with no certificate chain, which is self attestation: the credential
// signed its own statement, so there is nothing behind it to check.
const SELF_ATTESTED = isoCBOR.encode(
  new Map<string, unknown>([
    ['fmt', 'packed'],
    [
      'attStmt',
      new Map<string, unknown>([
        ['alg', -7],
        ['sig', new Uint8Array([9])],
      ]),
    ],
    ['authData', new Uint8Array([1, 2, 3])],
  ]) as never,
);

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
  (WebAuthnChallenge.findOne as any).mockResolvedValue(buildWebAuthnChallenge());
  (AuthEvent.count as any).mockResolvedValue(0);
  (getSystemConfig as any).mockResolvedValue({
    app_name: 'SeamlessAuth',
    rpid: 'localhost',
    origins: ['http://localhost:5137'],
    access_token_ttl: '15m',
    refresh_token_ttl: '1h',
    session_idle_ttl: '8h',
    authenticator_policy: {
      attachment: 'any',
      userVerification: 'required',
      attestation: 'none',
      requireKnownAuthenticator: false,
      syncedPasskeys: 'allow',
      aaguidAllowList: [],
      aaguidDenyList: [],
    },
  });
  (Credential.findAll as any).mockResolvedValue([]);
  (Credential.findOne as any).mockResolvedValue(null);
});

describe('GET /webauthn/register/start', () => {
  it('returns challenge', async () => {
    (Credential.findAll as any).mockResolvedValue([]);
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
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
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
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

  // The reported case in #222: an unrecognised value never reaches the controller,
  // so the refusal comes from request validation rather than the policy check.
  it('refuses an unrecognised attachment with the documented error body', async () => {
    const res = await request(app).get('/webauthn/register/start').query({ attachment: 'bogus' });

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({
      error: 'invalid_request',
      details: {
        issues: [expect.objectContaining({ path: ['attachment'] })],
      },
    });
    // A consumer reads `error` alone to learn why a call failed, so the raw
    // ZodError shape must not come back.
    expect(res.body).not.toHaveProperty('name', 'ZodError');
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

  it('offers both authenticator kinds when no attachment is requested', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);
    const [options] = (generateRegistrationOptions as any).mock.calls.at(-1);
    expect(options.authenticatorSelection).not.toHaveProperty('authenticatorAttachment');
  });

  it('narrows to roaming authenticators when a security key is requested', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app)
      .get('/webauthn/register/start')
      .query({ attachment: 'cross-platform' });

    expect(res.status).toBe(200);
    expect(generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        authenticatorSelection: expect.objectContaining({
          authenticatorAttachment: 'cross-platform',
        }),
      }),
    );
  });

  it('narrows to platform authenticators when asked for', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app)
      .get('/webauthn/register/start')
      .query({ attachment: 'platform' });

    expect(res.status).toBe(200);
    expect(generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        authenticatorSelection: expect.objectContaining({
          authenticatorAttachment: 'platform',
        }),
      }),
    );
  });

  it('rejects an unknown attachment', async () => {
    const res = await request(app)
      .get('/webauthn/register/start')
      .query({ attachment: 'usb-only' });

    expect(res.status).toBe(400);
  });

  it('pins the attachment when the deployment policy names one', async () => {
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      authenticator_policy: {
        attachment: 'cross-platform',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    });
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);
    expect(generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        authenticatorSelection: expect.objectContaining({
          authenticatorAttachment: 'cross-platform',
        }),
      }),
    );
  });

  it('lets a request agree with the pinned policy', async () => {
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      authenticator_policy: {
        attachment: 'cross-platform',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    });
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app)
      .get('/webauthn/register/start')
      .query({ attachment: 'cross-platform' });

    expect(res.status).toBe(200);
  });

  it('refuses a request that contradicts the pinned policy', async () => {
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      authenticator_policy: {
        attachment: 'cross-platform',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    });
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app)
      .get('/webauthn/register/start')
      .query({ attachment: 'platform' });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'attachment_not_allowed' });
    expect(generateRegistrationOptions).not.toHaveBeenCalled();
  });

  it('records a challenge rather than a success when options are issued', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);

    const types = (AuthEventService.log as any).mock.calls.map(([arg]: [any]) => arg.type);

    expect(types).toContain('webauthn_registration_challenge');
    // Abandoning here must leave no trace of a registration that never happened.
    expect(types).not.toContain('webauthn_registration_success');
    expect(types).not.toContain('registration_success');
  });

  // FIDO Server Requirements v2.3 requires RS1, RS256, ES256 and EdDSA. This pins
  // the advertised set so a library upgrade cannot quietly change what is offered:
  // the SimpleWebAuthn default is [-8, -7, -257] and omits RS1 entirely.
  it('advertises every algorithm the specification requires, weakest last', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);

    const [options] = (generateRegistrationOptions as any).mock.calls.at(-1);

    expect(options.supportedAlgorithmIDs).toEqual([-8, -7, -257, -65535]);
    // RS1 is SHA-1 based. It is offered because the specification requires it,
    // and ordered last so nothing picks it while a better option is available.
    expect(options.supportedAlgorithmIDs.at(-1)).toBe(-65535);
  });

  it('accepts only the algorithms it advertised', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockResolvedValue({ verified: false });

    await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    const [options] = (verifyRegistrationResponse as any).mock.calls.at(-1);

    expect(options.supportedAlgorithmIDs).toEqual([-8, -7, -257, -65535]);
  });

  // Registration used to ask for 'preferred' while the library default enforced
  // 'required', so a user on an authenticator that skips verification completed
  // the whole ceremony and was rejected at the last step.
  it('asks for exactly the verification it will enforce', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);

    const [options] = (generateRegistrationOptions as any).mock.calls.at(-1);

    expect(options.authenticatorSelection.userVerification).toBe('required');
  });

  it('follows a deployment that relaxes verification', async () => {
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'discouraged',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    });
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    await request(app).get('/webauthn/register/start');

    const [options] = (generateRegistrationOptions as any).mock.calls.at(-1);

    expect(options.authenticatorSelection.userVerification).toBe('discouraged');
  });

  it('asks for no attestation by default', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    await request(app).get('/webauthn/register/start');

    const [options] = (generateRegistrationOptions as any).mock.calls.at(-1);

    expect(options.attestationType).toBe('none');
  });

  it('requests attestation when the deployment asks for it', async () => {
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'direct',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    });
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    await request(app).get('/webauthn/register/start');

    const [options] = (generateRegistrationOptions as any).mock.calls.at(-1);

    expect(options.attestationType).toBe('direct');
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
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('rejects when the verified user is missing an email', async () => {
    const res = buildRes();

    await registerWebAuthn(buildReq({ user: { id: 'user-1', email: null } }), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });
});

describe('challenge is spent on every login outcome', () => {
  // The login path previously never cleared the challenge, so a captured
  // assertion stayed replayable until some later flow happened to overwrite it.
  it('spends the challenge even when verification fails', async () => {
    const record = buildWebAuthnChallenge({ purpose: 'authentication' });
    (WebAuthnChallenge.findOne as any).mockResolvedValue(record);
    (Credential.findOne as any).mockResolvedValue(buildCredential({ id: 'cred-1' }));

    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockRejectedValue(new Error('bad assertion'));

    await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'cred-1' } });

    expect(record.update).toHaveBeenCalledWith(
      expect.objectContaining({ consumedAt: expect.any(Date) }),
    );
  });

  it('spends the challenge on a successful login', async () => {
    const record = buildWebAuthnChallenge({ purpose: 'authentication' });
    (WebAuthnChallenge.findOne as any).mockResolvedValue(record);
    (Credential.findOne as any).mockResolvedValue(
      buildCredential({ id: 'cred-1', update: vi.fn() }),
    );
    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    });

    await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'cred-1' } });

    expect(record.update).toHaveBeenCalledWith(
      expect.objectContaining({ consumedAt: expect.any(Date) }),
    );
  });

  it('refuses a second attempt once the challenge is spent', async () => {
    (WebAuthnChallenge.findOne as any).mockResolvedValue(null);

    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'cred-1' } });

    expect(res.status).toBe(401);
  });
});

describe('verification policy reaches both verifiers', () => {
  it('enforces user verification at registration when the policy requires it', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockResolvedValue({ verified: false });

    await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    const [options] = (verifyRegistrationResponse as any).mock.calls.at(-1);

    expect(options.requireUserVerification).toBe(true);
  });

  it('stops enforcing it when the deployment relaxes the policy', async () => {
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      origins: ['http://localhost:5137'],
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'discouraged',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    });
    (User.findOne as any).mockResolvedValue(buildUser());
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockResolvedValue({ verified: false });

    await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    const [options] = (verifyRegistrationResponse as any).mock.calls.at(-1);

    expect(options.requireUserVerification).toBe(false);
  });
});

describe('authenticator policy at registration', () => {
  function policyConfig(overrides: Record<string, unknown>) {
    (getSystemConfig as any).mockResolvedValue({
      app_name: 'SeamlessAuth',
      rpid: 'localhost',
      origins: ['http://localhost:5137'],
      access_token_ttl: '15m',
      refresh_token_ttl: '1h',
      session_idle_ttl: '8h',
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'direct',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
        ...overrides,
      },
    });
  }

  async function registerWith(registrationInfo: Record<string, unknown>) {
    (User.findOne as any).mockResolvedValue(buildUser());
    (Credential.findAll as any).mockResolvedValue([]);
    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (signAccessToken as any).mockResolvedValue('access-token');
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');

    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        fmt: 'packed',
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'singleDevice',
        ...registrationInfo,
      },
    });

    return request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });
  }

  it('refuses a credential that can leave the device when syncing is blocked', async () => {
    policyConfig({ syncedPasskeys: 'block' });

    const res = await registerWith({ credentialDeviceType: 'multiDevice' });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'synced_passkey_not_allowed' });
    expect(Credential.create).not.toHaveBeenCalled();
  });

  it('admits a device-bound credential under the same policy', async () => {
    policyConfig({ syncedPasskeys: 'block' });

    const res = await registerWith({ credentialDeviceType: 'singleDevice' });

    expect(res.status).toBe(200);
    expect(Credential.create).toHaveBeenCalled();
  });

  it('refuses a model that is not on the allow list', async () => {
    policyConfig({ aaguidAllowList: ['ee882879-721c-4913-9775-3dfcce97072a'] });

    const res = await registerWith({ aaguid: 'deadbeef-0000-0000-0000-000000000000' });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'authenticator_not_allowed' });
  });

  it('admits a model that is on it', async () => {
    policyConfig({ aaguidAllowList: ['ee882879-721c-4913-9775-3dfcce97072a'] });

    const res = await registerWith({ aaguid: 'ee882879-721c-4913-9775-3dfcce97072a' });

    expect(res.status).toBe(200);
  });

  it('distinguishes the two refusals in the audit trail', async () => {
    policyConfig({ syncedPasskeys: 'block' });
    await registerWith({ credentialDeviceType: 'multiDevice' });

    const failure = (AuthEventService.log as any).mock.calls
      .map(([arg]: [any]) => arg)
      .find((arg: any) => arg.type === 'webauthn_registration_failed');

    expect(failure).toBeDefined();
    expect(failure.metadata.reason).toContain('backup eligible');
    expect(failure.metadata.deviceType).toBe('multiDevice');
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

  it('records how the credential identified itself', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    (Credential.findAll as any).mockResolvedValue([]);
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        fmt: 'packed',
        aaguid: 'ee882879-721c-4913-9775-3dfcce97072a',
        attestationObject: SELF_ATTESTED,
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    // The format alone cannot say which of the two 'packed' statements this was,
    // which is why the type is recorded beside it.
    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({ attestationFormat: 'packed', attestationType: 'self' }),
    );
  });

  it('does not claim an unattested credential was verified against metadata', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    (Credential.findAll as any).mockResolvedValue([]);
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        // What a deployment on the default posture gets: no statement to check.
        fmt: 'none',
        aaguid: '00000000-0000-0000-0000-000000000000',
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({
        attestationFormat: 'none',
        attestationType: 'none',
        attestationVerified: false,
      }),
    );
  });

  it('records the authenticator model the credential came from', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    (Credential.findAll as any).mockResolvedValue([]);
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        aaguid: 'ee882879-721c-4913-9775-3dfcce97072a',
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({ aaguid: 'ee882879-721c-4913-9775-3dfcce97072a' }),
    );
  });

  it('keeps an all-zero model rather than treating it as missing', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    (Credential.findAll as any).mockResolvedValue([]);
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        // An authenticator declining to identify itself, which is different from
        // never having recorded one.
        aaguid: '00000000-0000-0000-0000-000000000000',
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({ aaguid: '00000000-0000-0000-0000-000000000000' }),
    );
  });

  it('records exactly one success for a completed registration', async () => {
    const user = buildUser();

    (signAccessToken as any).mockResolvedValue('access-token');
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
    (User.findOne as any).mockResolvedValue(user);
    (Credential.findAll as any).mockResolvedValue([]);
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: false,
        credentialDeviceType: 'platform',
      },
    });

    (Credential.create as any).mockResolvedValue({});
    (Session.create as any).mockResolvedValue({ id: 'session-1' });

    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(200);

    const successes = (AuthEventService.log as any).mock.calls
      .map(([arg]: [any]) => arg.type)
      .filter((type: string) => type.endsWith('_success'));

    expect(successes).toEqual(['registration_success']);
  });

  it('rejects PRF-required registration when credential is not PRF-capable', async () => {
    const user = buildUser();

    (User.findOne as any).mockResolvedValue(user);
    // The flow's PRF requirement travels with the challenge it was issued for.
    (WebAuthnChallenge.findOne as any).mockResolvedValue(
      buildWebAuthnChallenge({
        purpose: 'registration',
        context: { prfRequested: true, requirePrf: true },
      }),
    );
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

  it('rejects verification when no live challenge exists', async () => {
    (User.findOne as any).mockResolvedValue(buildUser());
    (WebAuthnChallenge.findOne as any).mockResolvedValue(null);

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
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('rejects when there is no verified user', async () => {
    const res = buildRes();

    await verifyWebAuthnRegistration(
      buildReq({ user: undefined, body: { attestationResponse: {} } }),
      res,
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
  });

  it('completes registration and issues a session', async () => {
    const user = buildUser({ roles: undefined });
    (User.findOne as any).mockResolvedValue(user);
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
    expect(Credential.create).toHaveBeenCalled();
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
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
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
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
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
    expect(res.json).toHaveBeenCalledWith({ error: 'Not allowed' });
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
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
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
