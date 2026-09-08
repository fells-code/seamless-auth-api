import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';

/**
 * The enrollment gate itself, driven through the real auth middleware.
 *
 * Every other WebAuthn spec replaces `attachAuthMiddleware` with one that injects a user
 * whatever the route asked for, so none of them can tell an access-gated route from a
 * pre-auth one. These can, which is the point: `/login` and `/registration/register` both
 * mint an ephemeral token for an existing account from an email address alone, so an
 * enrollment route that accepts one hands the account to anyone who knows the address.
 */
vi.unmock('../../../src/middleware/attachAuthMiddleware.js');

const ENROLLED_USER = {
  id: 'user-1',
  email: 'test@example.com',
  phone: null,
  roles: ['user'],
};

let app: Application;

beforeAll(async () => {
  const { createApp } = await import('../../../src/app.js');

  app = await createApp();
});

beforeEach(async () => {
  const { validateBearerToken } = await import('../../../src/services/sessionService.js');

  vi.clearAllMocks();
  (validateBearerToken as any).mockResolvedValue(null);
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
});

describe('passkey enrollment requires an access session', () => {
  it.each([
    ['get', '/webauthn/register/start'],
    ['post', '/webauthn/register/finish'],
  ])('validates the bearer on %s %s as an access token', async (method, path) => {
    const { validateBearerToken } = await import('../../../src/services/sessionService.js');

    await (request(app) as any)[method](path).set('Authorization', 'Bearer a-token');

    expect(validateBearerToken).toHaveBeenCalledWith('a-token', 'access');
  });

  it.each([
    ['get', '/webauthn/register/start'],
    ['post', '/webauthn/register/finish'],
  ])('refuses %s %s when the bearer is not an access token', async (method, path) => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');

    // What `validateBearerToken` returns for an ephemeral token under an access
    // expectation: `verifyJwtWithKid` refuses the typ mismatch and yields null.
    const res = await (request(app) as any)
      [method](path)
      .set('Authorization', 'Bearer an-ephemeral-token');

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'unauthorized' });
    expect(generateRegistrationOptions).not.toHaveBeenCalled();
  });

  it.each([
    ['get', '/webauthn/register/start'],
    ['post', '/webauthn/register/finish'],
  ])('refuses %s %s with no bearer at all', async (method, path) => {
    const res = await (request(app) as any)[method](path);

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'missing bearer token' });
  });

  it('issues a challenge for a caller holding an access session', async () => {
    const { validateBearerToken } = await import('../../../src/services/sessionService.js');
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');

    (validateBearerToken as any).mockResolvedValue({
      user: ENROLLED_USER,
      sessionId: 'session-1',
    });
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });

    const res = await request(app)
      .get('/webauthn/register/start')
      .set('Authorization', 'Bearer an-access-token');

    expect(res.status).toBe(200);
    expect(res.body.challenge).toBe('challenge');
  });

  // The takeover the gate exists to stop, end to end: `/registration/register` answers an
  // address that already has an account with an ephemeral token for that account, and
  // enrollment used to accept it.
  it('refuses the ephemeral token a registration attempt hands back', async () => {
    const { validateBearerToken } = await import('../../../src/services/sessionService.js');

    const res = await request(app)
      .get('/webauthn/register/start')
      .set('Authorization', 'Bearer token-from-registration-register');

    expect(validateBearerToken).toHaveBeenCalledWith('token-from-registration-register', 'access');
    expect(res.status).toBe(401);
  });
});

describe('passkey login still takes a pre-auth session', () => {
  it.each([['/webauthn/login/start'], ['/webauthn/login/finish']])(
    'validates the bearer on post %s as an ephemeral token',
    async (path) => {
      const { validateBearerToken } = await import('../../../src/services/sessionService.js');

      await request(app).post(path).set('Authorization', 'Bearer a-token').send({});

      expect(validateBearerToken).toHaveBeenCalledWith('a-token', 'ephemeral');
    },
  );
});
