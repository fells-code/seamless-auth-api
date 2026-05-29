import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { OAuthIdentity } from '../../../src/models/oauthIdentities.js';
import { User } from '../../../src/models/users.js';
import {
  buildOAuthAuthorizationUrl,
  createOAuthState,
  exchangeOAuthCode,
  fetchOAuthProfile,
  getEnabledOAuthProviders,
  resolveOAuthRedirectUri,
  resolveOAuthUser,
  verifyOAuthState,
} from '../../../src/services/oauthService.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';
import { buildUser } from '../../factories/userFactory.js';

const provider = {
  id: 'google',
  name: 'Google',
  enabled: true,
  clientId: 'client-id',
  clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
  scopes: ['openid', 'email', 'profile'],
  redirectUris: [],
  subjectJsonPath: 'sub',
  emailJsonPath: 'email',
  emailVerifiedJsonPath: 'email_verified',
  nameJsonPath: 'name',
  allowSignup: true,
  accountLinking: 'email' as const,
  requireEmailVerified: false,
};

describe('oauthService', () => {
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

  it('lists only enabled providers when oauth login is enabled', async () => {
    await expect(getEnabledOAuthProviders()).resolves.toEqual([provider]);
  });

  it('creates verifiable signed state values', () => {
    const state = createOAuthState({
      providerId: 'google',
      redirectUri: 'https://app.example.com/oauth/callback',
      returnTo: 'https://app.example.com/',
    });

    expect(verifyOAuthState(state, 'google')).toEqual(
      expect.objectContaining({
        providerId: 'google',
        redirectUri: 'https://app.example.com/oauth/callback',
        returnTo: 'https://app.example.com/',
      }),
    );
    expect(verifyOAuthState(state, 'github')).toBeNull();
  });

  it('builds provider authorization URLs', () => {
    const state = 'state';
    const url = buildOAuthAuthorizationUrl({
      provider,
      redirectUri: 'https://app.example.com/oauth/callback',
      state,
    });

    expect(url).toContain('client_id=client-id');
    expect(url).toContain('response_type=code');
    expect(url).toContain('scope=openid+email+profile');
    expect(url).toContain('state=state');
    expect(url).not.toContain('nonce=');
  });

  it('adds an OIDC nonce when one is supplied for openid scopes', () => {
    const url = buildOAuthAuthorizationUrl({
      provider,
      redirectUri: 'https://app.example.com/oauth/callback',
      state: 'state',
      nonce: 'nonce-value',
    });

    expect(url).toContain('nonce=nonce-value');
  });

  it('rejects redirect URIs outside configured origins', async () => {
    await expect(
      resolveOAuthRedirectUri(provider, 'https://evil.example.com/oauth/callback'),
    ).rejects.toThrow('OAuth redirect URI is not allowed');
  });

  it('rejects redirect URI prefix lookalikes', async () => {
    await expect(
      resolveOAuthRedirectUri(provider, 'https://app.example.com.evil.test/oauth/callback'),
    ).rejects.toThrow('OAuth redirect URI is not allowed');
  });

  it('exchanges code and parses profile without exposing provider tokens', async () => {
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
          email: 'Person@Example.com',
          email_verified: true,
          name: 'Person Example',
        }),
      });

    const token = await exchangeOAuthCode({
      provider,
      code: 'code',
      redirectUri: 'https://app.example.com/oauth/callback',
    });
    const profile = await fetchOAuthProfile(provider, token);

    expect(token).toBe('provider-token');
    expect(profile).toEqual({
      subject: 'provider-user',
      email: 'person@example.com',
      emailVerified: true,
      name: 'Person Example',
      raw: {
        sub: 'provider-user',
        email: 'Person@Example.com',
        email_verified: true,
        name: 'Person Example',
      },
    });
  });

  it('rejects provider profiles with explicitly unverified email addresses', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        sub: 'provider-user',
        email: 'person@example.com',
        email_verified: false,
      }),
    });

    await expect(fetchOAuthProfile(provider, 'provider-token')).rejects.toThrow(
      'OAuth profile email is not verified',
    );
  });

  it('links an OAuth profile to an existing user', async () => {
    const user = buildUser({ id: 'user-1', email: 'person@example.com' });

    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(user);
    (OAuthIdentity.findOrCreate as any).mockResolvedValue([]);

    await expect(
      resolveOAuthUser(provider, {
        subject: 'provider-user',
        email: 'person@example.com',
        name: 'Person Example',
        raw: {},
      }),
    ).resolves.toBe(user);

    expect(OAuthIdentity.findOrCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          providerId: 'google',
          providerSubject: 'provider-user',
        },
        defaults: expect.objectContaining({
          userId: 'user-1',
          email: 'person@example.com',
        }),
      }),
    );
  });

  it('does not link an OAuth profile to an existing user when account linking is disabled', async () => {
    const user = buildUser({ id: 'user-1', email: 'person@example.com' });

    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(user);

    await expect(
      resolveOAuthUser(
        {
          ...provider,
          accountLinking: 'disabled',
        },
        {
          subject: 'provider-user',
          email: 'person@example.com',
          emailVerified: true,
          raw: {},
        },
      ),
    ).resolves.toBeNull();

    expect(OAuthIdentity.findOrCreate).not.toHaveBeenCalled();
  });
});
