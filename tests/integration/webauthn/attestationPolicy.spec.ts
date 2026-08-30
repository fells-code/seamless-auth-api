import { isoCBOR } from '@simplewebauthn/server/helpers';
import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { generateRefreshToken, hashRefreshToken, signAccessToken } from '../../../src/lib/token';
import { AuthEvent } from '../../../src/models/authEvents';
import { Credential } from '../../../src/models/credentials';
import { Session } from '../../../src/models/sessions';
import { User } from '../../../src/models/users';
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges';
import { AuthEventService } from '../../../src/services/authEventService';
import { hasMetadataStatement } from '../../../src/services/metadataServiceBootstrap';
import { buildUser } from '../../factories/userFactory';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory';

let app: Application;

const AAGUID = 'ee882879-721c-4913-9775-3dfcce97072a';

// The one piece that cannot be exercised here: the metadata blob is fetched at
// startup and this suite never brings it up. What matters is the answer it gives.
vi.mock('../../../src/services/metadataServiceBootstrap.js', () => ({
  hasMetadataStatement: vi.fn(),
}));

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

function attestationObject(fmt: string, attStmt: Map<string, unknown>) {
  return isoCBOR.encode(
    new Map<string, unknown>([
      ['fmt', fmt],
      ['attStmt', attStmt],
      ['authData', new Uint8Array([1, 2, 3])],
    ]) as never,
  );
}

/** Packed, signed by the credential's own key. Anyone can produce one. */
const SELF_ATTESTED = attestationObject(
  'packed',
  new Map<string, unknown>([
    ['alg', -7],
    ['sig', new Uint8Array([9])],
  ]),
);

/** Packed, carrying a manufacturer certificate chain. */
const MANUFACTURER_ATTESTED = attestationObject(
  'packed',
  new Map<string, unknown>([
    ['alg', -7],
    ['sig', new Uint8Array([9])],
    ['x5c', [new Uint8Array([0x30, 0x82, 0x01])]],
  ]),
);

function policy(overrides: Record<string, unknown> = {}) {
  return {
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
  };
}

async function verificationReturns(fmt: string, object: Uint8Array | undefined) {
  const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

  (verifyRegistrationResponse as any).mockResolvedValue({
    verified: true,
    registrationInfo: {
      fmt,
      aaguid: AAGUID,
      attestationObject: object,
      credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
      credentialBackedUp: false,
      credentialDeviceType: 'singleDevice',
    },
  });
}

function register() {
  return request(app)
    .post('/webauthn/register/finish')
    .send({ attestationResponse: {}, metadata: {} });
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (WebAuthnChallenge.findOne as any).mockResolvedValue(buildWebAuthnChallenge());
  (AuthEvent.count as any).mockResolvedValue(0);
  (User.findOne as any).mockResolvedValue(buildUser());
  (Credential.findAll as any).mockResolvedValue([]);
  (Credential.create as any).mockResolvedValue({});
  (Session.create as any).mockResolvedValue({ id: 'session-1' });
  (signAccessToken as any).mockResolvedValue('access-token');
  (generateRefreshToken as any).mockReturnValue('refresh-token');
  (hashRefreshToken as any).mockResolvedValue('hashed-refresh');
  (hasMetadataStatement as any).mockResolvedValue(false);
  (getSystemConfig as any).mockResolvedValue(policy());
});

describe('requireKnownAuthenticator: true', () => {
  beforeEach(() => {
    (getSystemConfig as any).mockResolvedValue(policy({ requireKnownAuthenticator: true }));
  });

  it('refuses a self attested credential, which the metadata service never sees', async () => {
    await verificationReturns('packed', SELF_ATTESTED);

    const res = await register();

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'authenticator_not_allowed' });
    expect(Credential.create).not.toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'webauthn_registration_failed',
        metadata: expect.objectContaining({ reason: expect.stringContaining('self attested') }),
      }),
    );
  });

  it('refuses a credential that presented no attestation at all', async () => {
    await verificationReturns('none', attestationObject('none', new Map()));

    const res = await register();

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'authenticator_not_allowed' });
    expect(Credential.create).not.toHaveBeenCalled();
  });

  it('admits a manufacturer attested credential the metadata service knows', async () => {
    await verificationReturns('packed', MANUFACTURER_ATTESTED);
    (hasMetadataStatement as any).mockResolvedValue(true);

    const res = await register();

    expect(res.status).toBe(200);
    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({ attestationType: 'basic', attestationVerified: true }),
    );
  });

  // Under 'none' no credential presents a chain, so applying the rule here would
  // refuse every registration rather than restricting anything.
  it('does not apply when the deployment never asked for attestation', async () => {
    (getSystemConfig as any).mockResolvedValue(
      policy({ requireKnownAuthenticator: true, attestation: 'none' }),
    );
    await verificationReturns('none', attestationObject('none', new Map()));

    const res = await register();

    expect(res.status).toBe(200);
  });
});

describe('requireKnownAuthenticator: false', () => {
  it('admits a self attested credential and records what it actually was', async () => {
    await verificationReturns('packed', SELF_ATTESTED);

    const res = await register();

    expect(res.status).toBe(200);
    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({
        attestationFormat: 'packed',
        attestationType: 'self',
        // The format alone reads the same as a manufacturer-signed statement, so
        // this is the field that keeps the two apart in an audit.
        attestationVerified: false,
      }),
    );
  });

  it('does not ask the metadata service about a credential it could not answer for', async () => {
    await verificationReturns('packed', SELF_ATTESTED);

    await register();

    expect(hasMetadataStatement).not.toHaveBeenCalled();
  });

  it('does not claim verification for a chain the metadata service does not list', async () => {
    await verificationReturns('packed', MANUFACTURER_ATTESTED);
    (hasMetadataStatement as any).mockResolvedValue(false);

    await register();

    expect(Credential.create).toHaveBeenCalledWith(
      expect.objectContaining({ attestationType: 'basic', attestationVerified: false }),
    );
  });
});
