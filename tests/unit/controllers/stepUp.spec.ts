import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  finishWebAuthnStepUp,
  getStepUpStatus,
  startWebAuthnStepUp,
} from '../../../src/controllers/stepUp.js';
import { Credential } from '../../../src/models/credentials.js';
import { Session } from '../../../src/models/sessions.js';
import { buildCredential } from '../../factories/credentialFactory.js';
import { buildSession } from '../../factories/sessionFactory.js';
import { buildUser } from '../../factories/userFactory.js';
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory';

function prfSalt(byte = 1) {
  return Buffer.alloc(32, byte).toString('base64url');
}

function buildReq(overrides: Record<string, unknown> = {}) {
  return {
    body: {},
    headers: {},
    ip: '127.0.0.1',
    user: buildUser(),
    sessionId: 'session-1',
    ...overrides,
  } as any;
}

function buildRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

beforeEach(() => {
  vi.clearAllMocks();
  challengeRecord.update = vi.fn();
  (WebAuthnChallenge.findOne as any).mockResolvedValue(challengeRecord);
});

const challengeRecord = buildWebAuthnChallenge({ purpose: 'step_up' });

describe('step-up controller', () => {
  it('starts a WebAuthn step-up challenge for authenticated users with credentials', async () => {
    const user = buildUser();
    const credential = buildCredential({ userId: user.id });
    (Credential.findAll as any).mockResolvedValue([credential]);
    (getSystemConfig as any).mockResolvedValue({ rpid: 'localhost' });

    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');
    (generateAuthenticationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const req = buildReq({ user });
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        allowCredentials: [{ id: credential.id, transports: credential.transports }],
        userVerification: 'required',
        rpID: 'localhost',
      }),
    );
    expect(WebAuthnChallenge.create).toHaveBeenCalledWith(
      expect.objectContaining({ purpose: 'step_up', challenge: 'challenge' }),
    );
    expect(res.json).toHaveBeenCalledWith({ challenge: 'challenge' });
  });

  it('starts a PRF-capable WebAuthn step-up challenge with caller salt', async () => {
    const user = buildUser();
    const credential = buildCredential({ id: 'prf-cred', userId: user.id, prfCapable: true });
    (Credential.findAll as any).mockResolvedValue([
      buildCredential({ id: 'regular-cred', userId: user.id, prfCapable: false }),
      credential,
    ]);
    (getSystemConfig as any).mockResolvedValue({ rpid: 'localhost' });

    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');
    (generateAuthenticationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const req = buildReq({
      user,
      body: { prf: { salt: prfSalt() } },
    });
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        allowCredentials: [{ id: credential.id, transports: credential.transports }],
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

  it('finishes WebAuthn step-up and records freshness on the current session', async () => {
    const user = buildUser();
    const credential = buildCredential({ id: 'cred-1', userId: user.id });
    const session = buildSession({ stepUpVerifiedAt: null, stepUpMethod: null });

    (Credential.findOne as any).mockResolvedValue(credential);
    (Session.findOne as any).mockResolvedValue(session);
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5137'],
      rpid: 'localhost',
    });

    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 2 },
    });

    const req = buildReq({
      user,
      body: { assertionResponse: { id: 'cred-1' } },
    });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(challengeRecord.update).toHaveBeenCalledWith(
      expect.objectContaining({ consumedAt: expect.any(Date) }),
    );
    expect(credential.update).toHaveBeenCalledWith(
      expect.objectContaining({
        counter: 2,
      }),
    );
    expect(session.stepUpVerifiedAt).toBeInstanceOf(Date);
    expect(session.stepUpMethod).toBe('webauthn');
    expect(session.save).toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Success',
        fresh: true,
        method: 'webauthn',
      }),
    );
  });

  it('does not update session freshness when verification fails', async () => {
    const user = buildUser();
    const credential = buildCredential({ id: 'cred-1', userId: user.id });

    (Credential.findOne as any).mockResolvedValue(credential);
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5137'],
      rpid: 'localhost',
    });

    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockResolvedValue({
      verified: false,
      authenticationInfo: { newCounter: 2 },
    });

    const req = buildReq({
      user,
      body: { assertionResponse: { id: 'cred-1' } },
    });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(Session.findOne).not.toHaveBeenCalled();
    expect(credential.update).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_failed' });
  });

  it('rejects WebAuthn step-up responses that include PRF output', async () => {
    const user = buildUser();
    const req = buildReq({
      user,
      body: {
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
      },
    });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(Credential.findOne).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'prf_output_not_allowed' });
  });

  it('reports step-up status for the current session', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' }),
    );

    const req = buildReq();
    const res = buildRes();

    await getStepUpStatus(req, res);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ fresh: true, method: 'webauthn' }),
    );
  });

  it('rejects status requests without an authenticated session', async () => {
    const req = buildReq({ user: undefined, sessionId: undefined });
    const res = buildRes();

    await getStepUpStatus(req, res);

    expect(Session.findOne).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
  });

  it('rejects status requests when the session cannot be found', async () => {
    (Session.findOne as any).mockResolvedValue(null);

    const req = buildReq();
    const res = buildRes();

    await getStepUpStatus(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
  });

  it('rejects starting step-up without an authenticated user', async () => {
    const req = buildReq({ user: undefined });
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(Credential.findAll).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
  });

  it('rejects starting step-up when the user has no matching credentials', async () => {
    (Credential.findAll as any).mockResolvedValue([]);

    const req = buildReq();
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_unavailable' });
  });

  it('defaults an absent body and credential list when starting step-up', async () => {
    (Credential.findAll as any).mockResolvedValue(null);

    const req = buildReq({ body: undefined });
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_unavailable' });
  });

  it('filters out credentials that do not match the requested credential id', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential({ id: 'other-cred' })]);

    const req = buildReq({ body: { credentialId: 'wanted-cred' } });
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_unavailable' });
  });

  it('reports when no PRF-capable credentials are available', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential({ prfCapable: false })]);

    const req = buildReq({ body: { prf: { salt: prfSalt() } } });
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_unavailable' });
  });

  it('returns 500 when generating step-up options fails', async () => {
    (Credential.findAll as any).mockResolvedValue([buildCredential()]);
    (getSystemConfig as any).mockResolvedValue({ rpid: 'localhost' });

    const { generateAuthenticationOptions } = await import('@simplewebauthn/server');
    (generateAuthenticationOptions as any).mockRejectedValue(new Error('boom'));

    const req = buildReq();
    const res = buildRes();

    await startWebAuthnStepUp(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: 'Internal server error' });
  });

  it('rejects finishing step-up without an authenticated session', async () => {
    const req = buildReq({ user: undefined, sessionId: undefined });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
  });

  it('rejects finishing step-up when the challenge or assertion id is missing', async () => {
    const user = buildUser();
    (WebAuthnChallenge.findOne as any).mockResolvedValue(null);
    const req = buildReq({ user, body: { assertionResponse: { id: 'cred-1' } } });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(Credential.findOne).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_failed' });
  });

  it('rejects finishing step-up when the credential is not found', async () => {
    const user = buildUser();
    (Credential.findOne as any).mockResolvedValue(null);

    const req = buildReq({ user, body: { assertionResponse: { id: 'cred-1' } } });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_failed' });
  });

  it('rejects finishing step-up when the session cannot be recorded', async () => {
    const user = buildUser();
    const credential = buildCredential({ id: 'cred-1', userId: user.id });

    (Credential.findOne as any).mockResolvedValue(credential);
    (Session.findOne as any).mockResolvedValue(null);
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5137'],
      rpid: 'localhost',
    });

    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 2 },
    });

    const req = buildReq({ user, body: { assertionResponse: { id: 'cred-1' } } });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(credential.update).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
  });

  it('returns 401 when verification throws during finish', async () => {
    const user = buildUser();
    const credential = buildCredential({ id: 'cred-1', userId: user.id });

    (Credential.findOne as any).mockResolvedValue(credential);
    (getSystemConfig as any).mockResolvedValue({
      origins: ['http://localhost:5137'],
      rpid: 'localhost',
    });

    const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
    (verifyAuthenticationResponse as any).mockRejectedValue(new Error('boom'));

    const req = buildReq({ user, body: { assertionResponse: { id: 'cred-1' } } });
    const res = buildRes();

    await finishWebAuthnStepUp(req, res);

    expect(challengeRecord.update).toHaveBeenCalledWith(
      expect.objectContaining({ consumedAt: expect.any(Date) }),
    );
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'step_up_failed' });
  });
});
