import request from 'supertest';
import { Application } from 'express';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { finishWebAuthnStepUp } from '../../../src/controllers/stepUp';
import { generateRefreshToken, signAccessToken } from '../../../src/lib/token';
import { AuthEvent } from '../../../src/models/authEvents';
import { Credential } from '../../../src/models/credentials';
import { Session } from '../../../src/models/sessions';
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges';
import { buildCredential } from '../../factories/credentialFactory';
import { buildSession } from '../../factories/sessionFactory';
import { buildUser } from '../../factories/userFactory';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory';

// The backup eligibility flag in an assertion is reported by the authenticator. WebAuthn
// Level 3 fixes it at registration, so the stored value is what decides hardware assurance,
// and only a registration whose attestation was verified can claim it.

let app: Application;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = buildUser();
      req.sessionId = 'session-1';
      req.attemptId = 'attempt-1';
      next();
    },
  };
});

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
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
});

async function assertWith(reported: 'singleDevice' | 'multiDevice') {
  const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
  (verifyAuthenticationResponse as any).mockResolvedValue({
    verified: true,
    authenticationInfo: { newCounter: 1, credentialDeviceType: reported, userVerified: true },
  });
}

async function signIn(stored: Record<string, unknown>, reported: 'singleDevice' | 'multiDevice') {
  (Credential.findOne as any).mockResolvedValue(
    buildCredential({ id: 'cred-1', update: vi.fn(), ...stored }),
  );
  (Session.create as any).mockResolvedValue({ id: 'session-1' });
  (signAccessToken as any).mockResolvedValue('access-token');
  (generateRefreshToken as any).mockReturnValue('refresh-token');
  await assertWith(reported);

  return request(app)
    .post('/webauthn/login/finish')
    .send({ assertionResponse: { id: 'cred-1' } });
}

function signedInPasskey() {
  const created = (Session.create as any).mock.calls[0]?.[0];
  return created?.authMethods?.find((m: any) => m.method === 'passkey');
}

async function stepUp(stored: Record<string, unknown>, reported: 'singleDevice' | 'multiDevice') {
  const user = buildUser();
  const session = buildSession({ authMethods: [] });
  (WebAuthnChallenge.findOne as any).mockResolvedValue(
    buildWebAuthnChallenge({ purpose: 'step_up' }),
  );
  (Credential.findOne as any).mockResolvedValue(
    buildCredential({ id: 'cred-1', userId: user.id, ...stored }),
  );
  (Session.findOne as any).mockResolvedValue(session);
  await assertWith(reported);

  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  await finishWebAuthnStepUp(
    {
      body: { assertionResponse: { id: 'cred-1' } },
      headers: {},
      ip: '127.0.0.1',
      user,
      sessionId: 'session-1',
    } as any,
    res,
  );
  return { res, session };
}

describe('passkey sign-in assurance', () => {
  it('refuses an assertion whose backup eligibility differs from the registered credential', async () => {
    const res = await signIn(
      { deviceType: 'multiDevice', attestationVerified: true },
      'singleDevice',
    );

    expect(res.status).toBe(401);
    expect(Session.create).not.toHaveBeenCalled();
  });

  it('does not call an unattested credential hardware bound', async () => {
    const res = await signIn(
      { deviceType: 'singleDevice', attestationType: 'none', attestationVerified: false },
      'singleDevice',
    );

    expect(res.status).toBe(200);
    expect(signedInPasskey()).toEqual(expect.objectContaining({ deviceBound: false }));
  });

  it('calls a device-bound credential with verified attestation hardware bound', async () => {
    const res = await signIn(
      { deviceType: 'singleDevice', attestationType: 'basic', attestationVerified: true },
      'singleDevice',
    );

    expect(res.status).toBe(200);
    expect(signedInPasskey()).toEqual(expect.objectContaining({ deviceBound: true }));
  });
});

describe('passkey step-up assurance', () => {
  it('refuses an assertion whose backup eligibility differs from the registered credential', async () => {
    const { res, session } = await stepUp(
      { deviceType: 'multiDevice', attestationVerified: true },
      'singleDevice',
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(session.authMethods).toEqual([]);
  });

  it('does not call an unattested credential hardware bound', async () => {
    const { session } = await stepUp(
      { deviceType: 'singleDevice', attestationType: 'none', attestationVerified: false },
      'singleDevice',
    );

    expect(session.authMethods).toEqual([
      expect.objectContaining({ method: 'passkey', deviceBound: false }),
    ]);
  });

  it('calls a device-bound credential with verified attestation hardware bound', async () => {
    const { session } = await stepUp(
      { deviceType: 'singleDevice', attestationType: 'basic', attestationVerified: true },
      'singleDevice',
    );

    expect(session.authMethods).toEqual([
      expect.objectContaining({ method: 'passkey', deviceBound: true }),
    ]);
  });
});
