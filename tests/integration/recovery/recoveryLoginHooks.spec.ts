import { isoCBOR } from '@simplewebauthn/server/helpers';
import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

let currentUser: any;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = currentUser;
      req.sessionId = 'session-1';
      req.recoverySession = true;
      next();
    },
  };
});

vi.mock('../../../src/services/metadataServiceBootstrap.js', () => ({
  hasMetadataStatement: vi.fn(async () => false),
  ensureMetadataServiceReady: vi.fn(async () => true),
}));

vi.mock('../../../src/services/loginHookService.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/services/loginHookService.js')>();
  return { ...actual, runLoginHook: vi.fn(async () => ({ outcome: 'skipped' })) };
});

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges.js';
import { runLoginHook } from '../../../src/services/loginHookService.js';
import { revokeSessionChain } from '../../../src/services/sessionService.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';
import { buildUser } from '../../factories/userFactory.js';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory.js';

let app: Application;

const NONE_ATTESTATION = isoCBOR.encode(
  new Map<string, unknown>([
    ['fmt', 'none'],
    ['attStmt', new Map()],
    ['authData', new Uint8Array([1, 2, 3])],
  ]) as never,
);

const recoverySession = {
  id: 'session-1',
  organizationId: null,
  authMethods: [{ method: 'recovery_code', at: new Date().toISOString() }],
};

function register() {
  return request(app)
    .post('/webauthn/register/finish')
    .send({ attestationResponse: {}, metadata: {} });
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(async () => {
  vi.clearAllMocks();
  currentUser = buildUser();

  const { verifyRegistrationResponse } = await import('@simplewebauthn/server');
  (verifyRegistrationResponse as any).mockResolvedValue({
    verified: true,
    registrationInfo: {
      fmt: 'none',
      aaguid: '00000000-0000-0000-0000-000000000000',
      attestationObject: NONE_ATTESTATION,
      credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
      credentialBackedUp: true,
      credentialDeviceType: 'multiDevice',
    },
  });

  (getSystemConfig as any).mockResolvedValue(
    buildSystemConfig({
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    }),
  );
  (User.findOne as any).mockResolvedValue(currentUser);
  (Credential.create as any).mockResolvedValue({ createdAt: new Date() });
  (WebAuthnChallenge.findOne as any).mockResolvedValue(
    buildWebAuthnChallenge({ purpose: 'registration' }),
  );
  (Session.findOne as any).mockResolvedValue(recoverySession);
  (Session.update as any).mockResolvedValue([1]);
});

describe('passkey enrollment from a recovery session', () => {
  it('runs the login hooks before lifting the restriction', async () => {
    vi.mocked(runLoginHook).mockImplementation(async (trigger) =>
      trigger === 'pre_token'
        ? { outcome: 'allowed', claims: { tier: 'gold' } }
        : { outcome: 'allowed', claims: null },
    );

    const res = await register();

    expect(res.status).toBe(200);
    expect(vi.mocked(runLoginHook).mock.calls.map(([trigger]) => trigger)).toEqual([
      'post_login',
      'pre_token',
    ]);
    expect(Session.update).toHaveBeenCalledWith(
      { recovery: false, hookClaims: { tier: 'gold' } },
      { where: { id: 'session-1', recovery: true, revokedAt: null, replacedBySessionId: null } },
    );
  });

  it('keeps the passkey but ends the session when post_login denies', async () => {
    vi.mocked(runLoginHook).mockResolvedValue({
      outcome: 'denied',
      userMessage: 'Your account is on hold.',
    });

    const res = await register();

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'login_denied', message: 'Your account is on hold.' });
    expect(Credential.create).toHaveBeenCalled();
    expect(revokeSessionChain).toHaveBeenCalledWith(recoverySession, expect.any(String));
    expect(Session.update).not.toHaveBeenCalled();
  });

  it('fails closed when a hook cannot be reached', async () => {
    vi.mocked(runLoginHook).mockResolvedValue({ outcome: 'failed_closed' });

    const res = await register();

    expect(res.status).toBe(503);
    expect(res.body).toEqual({ error: 'login_hook_unavailable' });
    expect(Session.update).not.toHaveBeenCalled();
  });
});
