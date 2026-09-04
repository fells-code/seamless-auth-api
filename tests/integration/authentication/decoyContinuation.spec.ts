import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { decoyPrincipalForSubject, decoySubjectFor } from '../../../src/services/decoyPrincipal.js';

/**
 * A decoy is only worth issuing if the fifteen endpoints that accept a pre-auth token
 * answer for it the way they answer for a real account. Otherwise `/login` stops
 * disclosing which identifiers exist and the very next request starts.
 *
 * These drive the real routes with a decoy principal in place of an authenticated user,
 * which is what `validateEphemeralToken` produces for a subject that resolves to no row.
 */

function decoyWithPhone(withPhone: boolean) {
  for (let i = 0; i < 100; i += 1) {
    const principal = decoyPrincipalForSubject(decoySubjectFor(`probe${i}@example.com`, 'email'));

    if ((principal.phone !== null) === withPhone) {
      return principal;
    }
  }

  throw new Error('no decoy of that shape found');
}

const DECOY = decoyWithPhone(true);
const PHONELESS_DECOY = decoyWithPhone(false);

let principal: ReturnType<typeof decoyPrincipalForSubject> = DECOY;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = principal;
      req.decoy = true;
      next();
    },
  };
});

vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: { create: vi.fn() },
}));

import { generateAuthenticationOptions, generateRegistrationOptions } from '@simplewebauthn/server';

import { signEphemeralToken } from '../../../src/lib/token.js';
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges.js';
import { generateEmailOTP, generatePhoneOTP } from '../../../src/utils/otp.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  principal = DECOY;
  (signEphemeralToken as any).mockResolvedValue('decoy-token');
  (generateRegistrationOptions as any).mockResolvedValue({
    challenge: 'challenge',
    rp: { id: 'localhost', name: 'Seamless' },
  });
  (generateAuthenticationOptions as any).mockResolvedValue({
    challenge: 'challenge',
    allowCredentials: [{ id: 'decoy-credential' }],
  });
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

describe('decoy continuation: OTP', () => {
  it.each([
    ['/otp/generate-email-otp'],
    ['/otp/generate-phone-otp'],
    ['/otp/generate-login-email-otp'],
    ['/otp/generate-login-phone-otp'],
  ])('reports success without sending for %s', async (path) => {
    const res = await request(app).get(path);

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('success');
    expect(res.body.token).toBe('decoy-token');
  });

  it('answers a phoneless decoy the way a phoneless account is answered', async () => {
    principal = PHONELESS_DECOY;

    const res = await request(app).get('/otp/generate-phone-otp');

    // About half of decoys are shaped without a phone so that a narrow login method list
    // proves nothing. Those have to answer 400 here like a real phoneless account, or
    // the shape that was hiding them becomes the thing that shows them.
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Invalid data' });
  });

  it('never sends a real message for a decoy', async () => {
    await request(app).get('/otp/generate-email-otp');
    await request(app).get('/otp/generate-phone-otp');

    expect(generateEmailOTP).not.toHaveBeenCalled();
    expect(generatePhoneOTP).not.toHaveBeenCalled();
  });

  it.each([
    ['/otp/verify-email-otp'],
    ['/otp/verify-phone-otp'],
    ['/otp/verify-login-email-otp'],
    ['/otp/verify-login-phone-otp'],
  ])('fails %s the way a wrong code fails', async (path) => {
    const res = await request(app).post(path).send({ verificationToken: '123456' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Not allowed' });
  });

  it('reports a disabled login method rather than success', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).get('/otp/generate-login-email-otp');

    // A deployment with email OTP off answers 403 for every identifier, so a decoy
    // that returned success here would be the one that stood out.
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'login_method_disabled' });
  });
});

describe('decoy continuation: magic link', () => {
  it('reports the link as sent without sending it', async () => {
    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('If an account exists, a login link has been sent.');
  });

  it('polls as an unclicked link forever', async () => {
    const res = await request(app).get('/magic-link/check');

    expect(res.status).toBe(204);
  });

  it('reports a disabled magic link rather than success', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'login_method_disabled' });
  });
});

describe('decoy continuation: WebAuthn', () => {
  it('returns a plausible registration challenge', async () => {
    const res = await request(app).get('/webauthn/register/start');

    expect(res.status).toBe(200);
    expect(res.body.challenge).toBe('challenge');
    expect(generateRegistrationOptions).toHaveBeenCalledWith(
      expect.objectContaining({ rpID: 'localhost', userName: DECOY.email }),
    );
  });

  it('returns a plausible login challenge with a credential to offer', async () => {
    const res = await request(app).post('/webauthn/login/start').send({});

    // A real account with no passkey answers 401 here. An empty allow-list would put
    // the decoy in that bucket and separate it from every account that has one.
    expect(res.status).toBe(200);
    expect(res.body.challenge).toBe('challenge');
    expect(generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        rpID: 'localhost',
        allowCredentials: [{ id: expect.any(String) }],
      }),
    );
  });

  it('stores no challenge for a decoy', async () => {
    await request(app).get('/webauthn/register/start');
    await request(app).post('/webauthn/login/start').send({});

    // A decoy is issued for any identifier a stranger can type. If probing one wrote a
    // row, closing the enumeration oracle would have opened a way to fill the disk.
    expect(WebAuthnChallenge.create).not.toHaveBeenCalled();
  });

  it('fails registration the way an expired ceremony fails', async () => {
    const res = await request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'Missing challenge' });
  });

  it('fails login the way a bad assertion fails', async () => {
    const res = await request(app)
      .post('/webauthn/login/finish')
      .send({ assertionResponse: { id: 'cred-1' } });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Authentication failed.' });
  });
});

describe('decoy continuation: TOTP', () => {
  it('fails the way a wrong code fails', async () => {
    const res = await request(app).post('/totp/verify-login').send({ code: '123456' });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'totp_verification_failed' });
  });
});
