import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  hashRefreshToken,
  signAccessToken,
} from '../../../src/lib/token.js';
import { OAuthIdentity } from '../../../src/models/oauthIdentities.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';
import { buildUser } from '../../factories/userFactory.js';

let app: Application;

const provider = {
  id: 'google',
  name: 'Google',
  enabled: true,
  clientId: 'client-id',
  clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
  scopes: ['openid', 'email'],
  redirectUri: 'http://localhost:5174/oauth/callback',
  redirectUris: ['http://localhost:5174/oauth/callback'],
  subjectJsonPath: 'sub',
  emailJsonPath: 'email',
  emailVerifiedJsonPath: 'email_verified',
  nameJsonPath: 'name',
  allowSignup: true,
  accountLinking: 'email' as const,
  requireEmailVerified: false,
};

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv('GOOGLE_CLIENT_SECRET', 'secret');
  (getSystemConfig as any).mockResolvedValue(
    buildSystemConfig({
      login_methods: ['passkey', 'oauth'],
      oauth_providers: [provider],
    }),
  );
});

describe('OAuth routes', () => {
  it('lists enabled OAuth providers without secrets', async () => {
    const res = await request(app).get('/oauth/providers');

    expect(res.status).toBe(200);
    expect(res.body.providers).toEqual([
      {
        id: 'google',
        name: 'Google',
        scopes: ['openid', 'email'],
      },
    ]);
    expect(JSON.stringify(res.body)).not.toContain('GOOGLE_CLIENT_SECRET');
  });

  it('starts OAuth login with a signed state and authorization URL', async () => {
    const res = await request(app).post('/oauth/google/start').send({
      redirectUri: 'http://localhost:5174/oauth/callback',
      returnTo: 'http://localhost:5174/dashboard',
    });

    expect(res.status).toBe(200);
    expect(res.body.provider.id).toBe('google');
    expect(res.body.state).toMatch(/\./);
    expect(res.body.authorizationUrl).toContain('client_id=client-id');
    expect(res.body.authorizationUrl).toContain('state=');
    expect(res.body.authorizationUrl).toContain('nonce=');
  });

  it('rejects redirect URI prefix lookalikes', async () => {
    const res = await request(app).post('/oauth/google/start').send({
      redirectUri: 'http://localhost:5174.evil.test/oauth/callback',
    });

    expect(res.status).toBe(400);
  });

  it('finishes OAuth login and issues a SeamlessAuth session', async () => {
    const start = await request(app).post('/oauth/google/start').send({
      redirectUri: 'http://localhost:5174/oauth/callback',
    });

    const user = buildUser({
      id: 'user-1',
      email: 'person@example.com',
      phone: 'oauth:google:provider-user',
      roles: ['user'],
    });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'provider-token' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          sub: 'provider-user',
          email: 'person@example.com',
          email_verified: true,
          name: 'Person Example',
        }),
      });

    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (OAuthIdentity.findOrCreate as any).mockResolvedValue([]);
    (User.findOne as any).mockResolvedValue(user);
    (Session.create as any).mockResolvedValue({ id: 'session-1' });
    (signAccessToken as any).mockResolvedValue('access-token');
    (generateRefreshToken as any).mockReturnValue('refresh-token');
    (hashRefreshToken as any).mockResolvedValue('refresh-hash');
    (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');

    const res = await request(app).post('/oauth/google/callback').send({
      code: 'oauth-code',
      state: start.body.state,
    });

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://oauth2.googleapis.com/token',
      expect.objectContaining({
        method: 'POST',
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://openidconnect.googleapis.com/v1/userinfo',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer provider-token',
        }),
      }),
    );
    expect(res.body).toEqual(
      expect.objectContaining({
        message: 'Success',
        token: 'access-token',
        sub: 'user-1',
      }),
    );
  });
});
