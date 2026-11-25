import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  decoyPrincipalForSubject,
  decoySubjectFor,
  registrationDecoySubjectFor,
} from '../../../src/services/decoyPrincipal.js';

/**
 * Runs the same request through each pre-auth route twice, once as a real account and
 * once as a decoy, and requires the two answers to match. Where `decoyContinuation.spec.ts`
 * pins what a decoy answers, this pins that it answers what a real account does.
 */

function findDecoy(matches: (p: ReturnType<typeof decoyPrincipalForSubject>) => boolean) {
  for (let i = 0; i < 500; i += 1) {
    const principal = decoyPrincipalForSubject(decoySubjectFor(`parity${i}@example.com`, 'email'));

    if (matches(principal)) {
      return principal;
    }
  }

  throw new Error('no decoy of that shape found');
}

const DECOY = findDecoy((p) => p.phone !== null && p.hasPasskey && p.prfCapable);

let caller: { user: unknown; decoy: boolean } = { user: DECOY, decoy: true };

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = caller.user;
      req.decoy = caller.decoy;
      req.attemptId = 'attempt-1';
      next();
    },
  };
});

import { verifyAuthenticationResponse } from '@simplewebauthn/server';

import { reissueEphemeralToken } from '../../../src/lib/token.js';
import { Credential } from '../../../src/models/credentials.js';
import { MagicLinkToken } from '../../../src/models/magicLinks.js';
import { User } from '../../../src/models/users.js';
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges.js';
import { buildCredential } from '../../factories/credentialFactory.js';
import { buildUser } from '../../factories/userFactory.js';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (getSystemConfig as any).mockResolvedValue({
    access_token_ttl: '15m',
    app_name: 'Seamless',
    rpid: 'localhost',
    origins: ['http://localhost:5137'],
    login_methods: ['passkey', 'magic_link', 'email_otp', 'phone_otp'],
    passkey_login_fallback_enabled: true,
    authenticator_policy: {
      userVerification: 'preferred',
      attachment: 'any',
      attestation: 'none',
    },
  });
});

/** A verified account with a passkey and no code pending, the most ordinary state. */
function realUser(overrides: Record<string, unknown> = {}) {
  return buildUser({
    verified: true,
    emailVerificationToken: null,
    emailVerificationTokenExpiry: null,
    phoneVerificationToken: null,
    phoneVerificationTokenExpiry: null,
    ...overrides,
  });
}

type Probe = (agent: typeof app) => request.Test;

async function answer(probe: Probe, as: 'real' | 'decoy', arrange: () => void) {
  caller = as === 'real' ? { user: realUser(), decoy: false } : { user: DECOY, decoy: true };
  arrange();

  const res = await probe(app);

  return {
    status: res.status,
    body: res.body,
    text: res.text,
    contentType: res.headers['content-type'] ?? null,
  };
}

async function expectParity(probe: Probe, arrangeReal: () => void = () => {}) {
  const real = await answer(probe, 'real', arrangeReal);
  const decoy = await answer(probe, 'decoy', () => {});

  expect(decoy).toEqual(real);

  return real;
}

describe('pre-auth parity: OTP verification with no code pending', () => {
  it.each([
    ['/otp/verify-email-otp'],
    ['/otp/verify-phone-otp'],
    ['/otp/verify-login-email-otp'],
    ['/otp/verify-login-phone-otp'],
  ])('%s answers a real account and a decoy alike', async (path) => {
    const real = await expectParity((agent) =>
      request(agent).post(path).send({ verificationToken: '123456' }),
    );

    expect(real.status).toBe(401);
    expect(real.body).toEqual({ error: 'Not allowed' });
  });
});

describe('pre-auth parity: WebAuthn login finish', () => {
  const prfAssertion = {
    assertionResponse: {
      id: 'cred-1',
      clientExtensionResults: { prf: { results: { first: 'AAAA' } } },
    },
  };

  it('refuses PRF output the same way', async () => {
    const real = await expectParity((agent) =>
      request(agent).post('/webauthn/login/finish').send(prfAssertion),
    );

    expect(real.status).toBe(400);
    expect(real.body).toEqual({ error: 'prf_output_not_allowed' });
  });

  it('answers an assertion with no challenge issued the same way', async () => {
    const real = await expectParity((agent) =>
      request(agent)
        .post('/webauthn/login/finish')
        .send({ assertionResponse: { id: 'cred-1' } }),
    );

    expect(real.status).toBe(401);
  });

  it('answers an assertion over the wrong challenge the same way', async () => {
    const real = await expectParity(
      (agent) =>
        request(agent)
          .post('/webauthn/login/finish')
          .send({ assertionResponse: { id: 'cred-1' } }),
      () => {
        (WebAuthnChallenge.findOne as any).mockResolvedValue(buildWebAuthnChallenge());
        (Credential.findOne as any).mockResolvedValue(buildCredential({ id: 'cred-1' }));
        (verifyAuthenticationResponse as any).mockRejectedValue(new Error('Unexpected challenge'));
      },
    );

    expect(real.status).toBe(401);
    expect(real.body).toEqual({ error: 'Authentication failed.' });
  });

  it.each([[{}], [{ id: 'cred\u0000' }], [{ id: 7 }], [{ id: 'x'.repeat(2000) }]])(
    'answers a malformed credential id the same way (%o)',
    async (assertionResponse) => {
      const real = await expectParity(
        (agent) => request(agent).post('/webauthn/login/finish').send({ assertionResponse }),
        () => {
          (WebAuthnChallenge.findOne as any).mockResolvedValue(buildWebAuthnChallenge());
          (Credential.findOne as any).mockRejectedValue(new Error('invalid input syntax'));
        },
      );

      expect(real.status).toBe(401);
      expect(Credential.findOne).not.toHaveBeenCalled();
    },
  );
});

describe('pre-auth parity: magic link polling', () => {
  it.each([
    [{ ip_hash: 'another-ip', user_agent_hash: null }],
    [{ ip_hash: null, user_agent_hash: 'another-agent' }],
  ])('answers a pending link polled from another device as unclicked (%o)', async (hashes) => {
    const real = await expectParity(
      (agent) => request(agent).get('/magic-link/check').set('User-Agent', 'probe'),
      () => {
        (User.findOne as any).mockResolvedValue(realUser());
        (MagicLinkToken.findOne as any).mockResolvedValue({
          id: 'link-1',
          user_id: 'user-1',
          attempt_id: 'attempt-1',
          used_at: null,
          expires_at: new Date(Date.now() + 60_000),
          ...hashes,
        });
      },
    );

    expect(real.status).toBe(204);
  });
});

/**
 * Whether a sign-up has a phone is up to whoever registered it, and a registration decoy
 * cannot remember what was submitted. Every shape on either side has to answer alike.
 */
describe('pre-auth parity: registration phone OTP for an unclaimed sign-up', () => {
  const registrationDecoys = [true, false].map((withPhone) => {
    for (let i = 0; i < 500; i += 1) {
      const candidate = decoyPrincipalForSubject(registrationDecoySubjectFor(`reg${i}@x.com`));

      if ((candidate.phone !== null) === withPhone) return candidate;
    }

    throw new Error('no registration decoy of that shape found');
  });

  const signUps = [
    buildUser({ verified: false, phone: '+14155552671', phoneVerified: false }),
    buildUser({ verified: false, phone: null }),
  ];

  it('answers every sign-up and every registration decoy alike', async () => {
    (reissueEphemeralToken as any).mockResolvedValue('token');

    const answers = [];

    for (const user of signUps) {
      caller = { user, decoy: false };
      const res = await request(app).get('/otp/generate-phone-otp');
      answers.push({ status: res.status, body: res.body });
    }

    for (const user of registrationDecoys) {
      caller = { user, decoy: true };
      const res = await request(app).get('/otp/generate-phone-otp');
      answers.push({ status: res.status, body: res.body });
    }

    expect(answers).toEqual(
      answers.map(() => ({ status: 200, body: { message: 'success', token: 'token' } })),
    );
  });
});
