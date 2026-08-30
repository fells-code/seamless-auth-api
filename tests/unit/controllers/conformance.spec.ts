import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig';
import {
  assertionOptions,
  assertionResult,
  attestationOptions,
  attestationResult,
} from '../../../src/controllers/conformance';
import { resetConformanceStore } from '../../../src/services/conformanceStore';

// The library is stubbed by the shared setup here, which is the point: these are the
// paths a real authenticator cannot produce, such as a verification that reports
// `verified: false` instead of throwing.

function buildRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

function clientData(challenge: string, type = 'webauthn.create') {
  return Buffer.from(JSON.stringify({ type, challenge, origin: 'http://localhost:5137' })).toString(
    'base64url',
  );
}

async function issueRegistrationCeremony(challenge: string) {
  (generateRegistrationOptions as any).mockResolvedValue({ challenge });
  const res = buildRes();
  await attestationOptions({ body: { username: 'a@example.com', displayName: 'A' } } as any, res);
  return res;
}

async function registerCredential(credentialId: string) {
  await issueRegistrationCeremony('reg-challenge');
  (verifyRegistrationResponse as any).mockResolvedValue({
    verified: true,
    registrationInfo: {
      credential: { id: credentialId, publicKey: new Uint8Array([1]), counter: 0 },
    },
  });
  await attestationResult(
    {
      body: { id: credentialId, response: { clientDataJSON: clientData('reg-challenge') } },
    } as any,
    buildRes(),
  );
}

beforeEach(() => {
  resetConformanceStore();
  (getSystemConfig as any).mockResolvedValue({
    app_name: 'SeamlessAuth',
    rpid: 'localhost',
    origins: ['http://localhost:5137'],
  });
});

describe('attestationOptions', () => {
  it('answers the conformance envelope when option generation fails', async () => {
    (getSystemConfig as any).mockRejectedValue(new Error('config unavailable'));
    const res = buildRes();

    await attestationOptions({ body: { username: 'a@example.com', displayName: 'A' } } as any, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Could not generate attestation options',
    });
  });
});

describe('attestationResult', () => {
  it('fails a body carrying no client data at all', async () => {
    const res = buildRes();

    await attestationResult({ body: { id: 'abc' } } as any, res);

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'No outstanding registration ceremony for this challenge',
    });
  });

  it('reports a verification that rejects with something other than an Error', async () => {
    await issueRegistrationCeremony('reg-challenge');
    (verifyRegistrationResponse as any).mockRejectedValue('not an error');
    const res = buildRes();

    await attestationResult(
      { body: { response: { clientDataJSON: clientData('reg-challenge') } } } as any,
      res,
    );

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Registration verification failed',
    });
  });

  it('fails a verification that reports unverified without throwing', async () => {
    await issueRegistrationCeremony('reg-challenge');
    (verifyRegistrationResponse as any).mockResolvedValue({ verified: false });
    const res = buildRes();

    await attestationResult(
      { body: { response: { clientDataJSON: clientData('reg-challenge') } } } as any,
      res,
    );

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Registration response could not be verified',
    });
  });

  it('answers the envelope when the handler itself fails', async () => {
    await issueRegistrationCeremony('reg-challenge');
    (getSystemConfig as any).mockRejectedValue(new Error('config unavailable'));
    const res = buildRes();

    await attestationResult(
      { body: { response: { clientDataJSON: clientData('reg-challenge') } } } as any,
      res,
    );

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Could not process attestation result',
    });
  });
});

describe('assertionOptions', () => {
  it('answers the envelope when option generation fails', async () => {
    (generateAuthenticationOptions as any).mockRejectedValue(new Error('boom'));
    const res = buildRes();

    await assertionOptions({ body: {} } as any, res);

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Could not generate assertion options',
    });
  });
});

describe('assertionResult', () => {
  async function issueAuthenticationCeremony(challenge: string) {
    (generateAuthenticationOptions as any).mockResolvedValue({ challenge });
    await assertionOptions({ body: {} } as any, buildRes());
  }

  it('fails when the asserted credential was never registered', async () => {
    await issueAuthenticationCeremony('auth-challenge');
    const res = buildRes();

    await assertionResult(
      {
        body: {
          id: 'unknown',
          response: { clientDataJSON: clientData('auth-challenge', 'webauthn.get') },
        },
      } as any,
      res,
    );

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Credential is not registered',
    });
  });

  it('reports a verification that rejects with something other than an Error', async () => {
    await registerCredential('cred-1');
    await issueAuthenticationCeremony('auth-challenge');
    (verifyAuthenticationResponse as any).mockRejectedValue('not an error');
    const res = buildRes();

    await assertionResult(
      {
        body: {
          id: 'cred-1',
          response: { clientDataJSON: clientData('auth-challenge', 'webauthn.get') },
        },
      } as any,
      res,
    );

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Authentication verification failed',
    });
  });

  it('fails a verification that reports unverified without throwing', async () => {
    await registerCredential('cred-1');
    await issueAuthenticationCeremony('auth-challenge');
    (verifyAuthenticationResponse as any).mockResolvedValue({ verified: false });
    const res = buildRes();

    await assertionResult(
      {
        body: {
          id: 'cred-1',
          response: { clientDataJSON: clientData('auth-challenge', 'webauthn.get') },
        },
      } as any,
      res,
    );

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Authentication response could not be verified',
    });
  });

  it('answers the envelope when the handler itself fails', async () => {
    await registerCredential('cred-1');
    await issueAuthenticationCeremony('auth-challenge');
    (getSystemConfig as any).mockRejectedValue(new Error('config unavailable'));
    const res = buildRes();

    await assertionResult(
      {
        body: {
          id: 'cred-1',
          response: { clientDataJSON: clientData('auth-challenge', 'webauthn.get') },
        },
      } as any,
      res,
    );

    expect(res.json).toHaveBeenCalledWith({
      status: 'failed',
      errorMessage: 'Could not process assertion result',
    });
  });
});
