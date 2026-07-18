import { createHmac } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { OAuthIdentity } from '../../../src/models/oauthIdentities.js';
import { User } from '../../../src/models/users.js';
import {
  buildOAuthAuthorizationUrl,
  clearOAuthStateReplayCache,
  consumeOAuthState,
  createOAuthPkceCodeChallenge,
  createOAuthPkceCodeVerifier,
  createOAuthState,
  exchangeOAuthCode,
  fetchOAuthProfile,
  getEnabledOAuthProviders,
  getOAuthProvider,
  resolveOAuthRedirectUri,
  resolveOAuthUser,
  serializeOAuthProvider,
  verifyOAuthState,
} from '../../../src/services/oauthService.js';

function signState(payload: Record<string, unknown>, secret: string) {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function withEnv(overrides: Record<string, string | undefined>, fn: () => void) {
  const previous: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(overrides)) {
    previous[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    fn();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}
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
    clearOAuthStateReplayCache();
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

  it('consumes OAuth state only once per process', () => {
    const state = createOAuthState({
      providerId: 'google',
      redirectUri: 'https://app.example.com/oauth/callback',
    });

    expect(consumeOAuthState(state, 'google')).toEqual(
      expect.objectContaining({
        providerId: 'google',
      }),
    );
    expect(consumeOAuthState(state, 'google')).toBeNull();
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

  it('adds PKCE challenge parameters when supplied', () => {
    const state = createOAuthState({
      providerId: 'google',
      redirectUri: 'https://app.example.com/oauth/callback',
    });
    const payload = verifyOAuthState(state, 'google');

    expect(payload).not.toBeNull();

    const codeVerifier = createOAuthPkceCodeVerifier(provider, payload!);
    const codeChallenge = createOAuthPkceCodeChallenge(provider, payload!);
    const url = buildOAuthAuthorizationUrl({
      provider,
      redirectUri: 'https://app.example.com/oauth/callback',
      state,
      codeChallenge,
    });

    expect(codeVerifier).toEqual(expect.any(String));
    expect(codeChallenge).toEqual(expect.any(String));
    expect(url).toContain('code_challenge=');
    expect(url).toContain('code_challenge_method=S256');
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
      codeVerifier: 'pkce-verifier',
    });
    const profile = await fetchOAuthProfile(provider, token);

    expect(token).toBe('provider-token');
    expect((fetchMock.mock.calls[0][1]?.body as URLSearchParams).get('code_verifier')).toBe(
      'pkce-verifier',
    );
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

  it('creates a new user with a null phone when no existing account matches', async () => {
    const created = buildUser({ id: 'user-2', email: 'new@example.com', phone: null });

    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockResolvedValue(created);
    (OAuthIdentity.findOrCreate as any).mockResolvedValue([]);

    await expect(
      resolveOAuthUser(provider, {
        subject: 'provider-user',
        email: 'new@example.com',
        emailVerified: true,
        name: 'New Person',
        raw: {},
      }),
    ).resolves.toBe(created);

    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'new@example.com',
        phone: null,
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

  it('returns no providers when oauth login is not enabled', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ login_methods: ['passkey'], oauth_providers: [provider] }),
    );

    await expect(getEnabledOAuthProviders()).resolves.toEqual([]);
  });

  it('serializes a provider to its public shape', () => {
    expect(serializeOAuthProvider(provider)).toEqual({
      id: 'google',
      name: 'Google',
      scopes: ['openid', 'email', 'profile'],
    });
  });

  it('defaults serialized scopes to an empty list', () => {
    expect(serializeOAuthProvider({ ...provider, scopes: undefined } as any)).toEqual({
      id: 'google',
      name: 'Google',
      scopes: [],
    });
  });

  it('looks up an enabled provider by id and returns null when unknown', async () => {
    await expect(getOAuthProvider('google')).resolves.toEqual(provider);
    await expect(getOAuthProvider('github')).resolves.toBeNull();
  });

  it('uses the state secret from OAUTH_STATE_SECRET when configured', () => {
    withEnv({ OAUTH_STATE_SECRET: 'explicit-secret', API_SERVICE_TOKEN: undefined }, () => {
      const state = createOAuthState({
        providerId: 'google',
        redirectUri: 'https://app.example.com/oauth/callback',
      });

      expect(verifyOAuthState(state, 'google')).not.toBeNull();
    });
  });

  it('falls back to API_SERVICE_TOKEN for the state secret', () => {
    withEnv({ OAUTH_STATE_SECRET: undefined, API_SERVICE_TOKEN: 'service-token' }, () => {
      const state = createOAuthState({
        providerId: 'google',
        redirectUri: 'https://app.example.com/oauth/callback',
      });

      expect(verifyOAuthState(state, 'google')).not.toBeNull();
    });
  });

  it('requires a state secret in production', () => {
    withEnv(
      { NODE_ENV: 'production', OAUTH_STATE_SECRET: undefined, API_SERVICE_TOKEN: undefined },
      () => {
        expect(() =>
          createOAuthState({
            providerId: 'google',
            redirectUri: 'https://app.example.com/oauth/callback',
          }),
        ).toThrow('OAUTH_STATE_SECRET or API_SERVICE_TOKEN is required in production.');
      },
    );
  });

  it('accepts a requested redirect URI that matches a configured origin', async () => {
    await expect(
      resolveOAuthRedirectUri(provider, 'http://localhost:5174/oauth/callback'),
    ).resolves.toBe('http://localhost:5174/oauth/callback');
  });

  it('accepts a requested redirect URI listed in the provider allowlist', async () => {
    await expect(
      resolveOAuthRedirectUri(
        { ...provider, redirectUris: ['https://app.example.com/oauth/callback'] },
        'https://app.example.com/oauth/callback',
      ),
    ).resolves.toBe('https://app.example.com/oauth/callback');
  });

  it('falls back to the provider default redirect URI', async () => {
    await expect(
      resolveOAuthRedirectUri({ ...provider, redirectUri: 'https://cfg.example.com/cb' }),
    ).resolves.toBe('https://cfg.example.com/cb');
  });

  it('derives a redirect URI from the first configured origin', async () => {
    await expect(resolveOAuthRedirectUri(provider)).resolves.toBe(
      'http://localhost:5174/oauth/callback',
    );
  });

  it('rejects malformed state values without a signature', () => {
    expect(verifyOAuthState('no-signature', 'google')).toBeNull();
  });

  it('rejects state values with a tampered signature', () => {
    const state = createOAuthState({
      providerId: 'google',
      redirectUri: 'https://app.example.com/oauth/callback',
    });
    const [encoded] = state.split('.');

    expect(verifyOAuthState(`${encoded}.tampered`, 'google')).toBeNull();
  });

  it('rejects state values whose payload is not valid JSON', () => {
    withEnv({ OAUTH_STATE_SECRET: 'craft-secret' }, () => {
      const encoded = Buffer.from('not-json', 'utf8').toString('base64url');
      const signature = createHmac('sha256', 'craft-secret').update(encoded).digest('base64url');

      expect(verifyOAuthState(`${encoded}.${signature}`, 'google')).toBeNull();
    });
  });

  it('rejects state payloads with a non-string redirect URI', () => {
    withEnv({ OAUTH_STATE_SECRET: 'craft-secret' }, () => {
      const state = signState(
        { providerId: 'google', redirectUri: 42, createdAt: Date.now(), nonce: 'n' },
        'craft-secret',
      );

      expect(verifyOAuthState(state, 'google')).toBeNull();
    });
  });

  it('rejects state payloads with a non-numeric createdAt', () => {
    withEnv({ OAUTH_STATE_SECRET: 'craft-secret' }, () => {
      const state = signState(
        { providerId: 'google', redirectUri: 'https://app.example.com/cb', createdAt: 'soon' },
        'craft-secret',
      );

      expect(verifyOAuthState(state, 'google')).toBeNull();
    });
  });

  it('rejects expired state payloads', () => {
    withEnv({ OAUTH_STATE_SECRET: 'craft-secret' }, () => {
      const state = signState(
        {
          providerId: 'google',
          redirectUri: 'https://app.example.com/cb',
          createdAt: Date.now() - 11 * 60 * 1000,
          nonce: 'n',
        },
        'craft-secret',
      );

      expect(verifyOAuthState(state, 'google')).toBeNull();
    });
  });

  it('returns null when consuming an invalid state value', () => {
    expect(consumeOAuthState('invalid', 'google')).toBeNull();
  });

  it('purges expired replay-cache entries when consuming state', () => {
    vi.useFakeTimers();
    try {
      const base = new Date('2026-06-01T00:00:00.000Z');
      vi.setSystemTime(base);

      const first = createOAuthState({
        providerId: 'google',
        redirectUri: 'https://app.example.com/oauth/callback',
      });
      expect(consumeOAuthState(first, 'google')).not.toBeNull();

      vi.setSystemTime(new Date(base.getTime() + 11 * 60 * 1000));

      const second = createOAuthState({
        providerId: 'google',
        redirectUri: 'https://app.example.com/oauth/callback',
      });
      expect(consumeOAuthState(second, 'google')).not.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects requested redirect URIs that cannot be parsed', async () => {
    await expect(resolveOAuthRedirectUri(provider, 'not a valid url')).rejects.toThrow(
      'OAuth redirect URI is not allowed',
    );
  });

  it('rejects redirects when configured fallback origins are unparseable', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({
        login_methods: ['passkey', 'oauth'],
        oauth_providers: [provider],
        origins: ['not-a-url'],
      }),
    );

    await expect(
      resolveOAuthRedirectUri(provider, 'https://app.example.com/oauth/callback'),
    ).rejects.toThrow('OAuth redirect URI is not allowed');
  });

  it('accepts a redirect that matches the provider default in a combined allowlist', async () => {
    await expect(
      resolveOAuthRedirectUri(
        {
          ...provider,
          redirectUris: ['https://a.example.com/cb'],
          redirectUri: 'https://b.example.com/cb',
        },
        'https://b.example.com/cb',
      ),
    ).resolves.toBe('https://b.example.com/cb');
  });

  it('resolves nested profile fields and rejects broken nesting paths', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ sub: 'flat-value', email: 'person@example.com' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      fetchOAuthProfile({ ...provider, subjectJsonPath: 'sub.id' }, 'token'),
    ).rejects.toThrow('OAuth profile did not include a provider subject');
  });

  it('skips optional profile fields that have no configured json path', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ sub: 'provider-user', email: 'person@example.com', name: 'Ignored' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const leanProvider: any = { ...provider };
    delete leanProvider.emailVerifiedJsonPath;
    delete leanProvider.nameJsonPath;

    const profile = await fetchOAuthProfile(leanProvider, 'token');

    expect(profile).not.toHaveProperty('name');
    expect(profile).not.toHaveProperty('emailVerified');
  });

  it('rejects nesting paths whose intermediate segment is missing', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ email: 'person@example.com' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      fetchOAuthProfile({ ...provider, subjectJsonPath: 'missing.id' }, 'token'),
    ).rejects.toThrow('OAuth profile did not include a provider subject');
  });

  it('builds an allowlist from a provider that only sets a single redirect URI', async () => {
    const singleRedirect: any = { ...provider };
    delete singleRedirect.redirectUris;
    singleRedirect.redirectUri = 'https://single.example.com/cb';

    await expect(
      resolveOAuthRedirectUri(singleRedirect, 'https://single.example.com/cb'),
    ).resolves.toBe('https://single.example.com/cb');
  });

  it('omits PKCE parameters when the provider disables PKCE', () => {
    const noPkceProvider = { ...provider, pkce: false };
    const payload = {
      providerId: 'google',
      redirectUri: 'https://app.example.com/cb',
      nonce: 'n',
      createdAt: Date.now(),
    };

    expect(createOAuthPkceCodeVerifier(noPkceProvider as any, payload)).toBeUndefined();
    expect(createOAuthPkceCodeChallenge(noPkceProvider as any, payload)).toBeUndefined();
  });

  it('omits the scope parameter when a provider has no scopes', () => {
    const url = buildOAuthAuthorizationUrl({
      provider: { ...provider, scopes: [] },
      redirectUri: 'https://app.example.com/oauth/callback',
      state: 'state',
      nonce: 'nonce-value',
    });

    expect(url).not.toContain('scope=');
    expect(url).not.toContain('nonce=');
  });

  it('throws when the provider client secret env is not configured', async () => {
    await expect(
      exchangeOAuthCode({
        provider: { ...provider, clientSecretEnv: 'MISSING_SECRET_ENV' },
        code: 'code',
        redirectUri: 'https://app.example.com/oauth/callback',
      }),
    ).rejects.toThrow('OAuth client secret env "MISSING_SECRET_ENV" is not configured');
  });

  it('throws when the token exchange responds with a non-ok status', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 400 });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      exchangeOAuthCode({
        provider,
        code: 'code',
        redirectUri: 'https://app.example.com/oauth/callback',
      }),
    ).rejects.toThrow('OAuth token exchange failed with status 400');
  });

  it('throws when the token response lacks an access token', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      exchangeOAuthCode({
        provider,
        code: 'code',
        redirectUri: 'https://app.example.com/oauth/callback',
      }),
    ).rejects.toThrow('OAuth token response did not include an access token');
  });

  it('throws when the profile fetch responds with a non-ok status', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 401 });
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchOAuthProfile(provider, 'token')).rejects.toThrow(
      'OAuth profile fetch failed with status 401',
    );
  });

  it('throws when the profile omits a provider subject', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ email: 'person@example.com' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchOAuthProfile(provider, 'token')).rejects.toThrow(
      'OAuth profile did not include a provider subject',
    );
  });

  it('throws when the profile omits an email address', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ sub: 'provider-user' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchOAuthProfile(provider, 'token')).rejects.toThrow(
      'OAuth profile did not include an email address',
    );
  });

  it('parses a string email_verified flag and preserves a numeric subject', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ sub: 12345, email: 'person@example.com', email_verified: 'true' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchOAuthProfile(provider, 'token')).resolves.toEqual({
      subject: '12345',
      email: 'person@example.com',
      emailVerified: true,
      raw: { sub: 12345, email: 'person@example.com', email_verified: 'true' },
    });
  });

  it('omits emailVerified when the provider does not report it', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ sub: 'provider-user', email: 'person@example.com' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const profile = await fetchOAuthProfile(provider, 'token');

    expect(profile).not.toHaveProperty('emailVerified');
    expect(profile).not.toHaveProperty('name');
  });

  it('rejects unverified emails when the provider requires verification', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ sub: 'provider-user', email: 'person@example.com' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      fetchOAuthProfile({ ...provider, requireEmailVerified: true }, 'token'),
    ).rejects.toThrow('OAuth profile email is not verified');
  });

  it('returns the linked user for an existing identity', async () => {
    const user = buildUser({ id: 'user-9', email: 'linked@example.com' });

    (OAuthIdentity.findOne as any).mockResolvedValue({ userId: 'user-9' });
    (User.findByPk as any).mockResolvedValue(user);

    await expect(
      resolveOAuthUser(provider, {
        subject: 'provider-user',
        email: 'linked@example.com',
        raw: {},
      }),
    ).resolves.toBe(user);

    expect(User.findByPk).toHaveBeenCalledWith('user-9');
    expect(OAuthIdentity.findOrCreate).not.toHaveBeenCalled();
  });

  it('falls through to email lookup when the identity references a missing user', async () => {
    const emailUser = buildUser({ id: 'user-10', email: 'person@example.com' });

    (OAuthIdentity.findOne as any).mockResolvedValue({ userId: 'ghost' });
    (User.findByPk as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(emailUser);
    (OAuthIdentity.findOrCreate as any).mockResolvedValue([]);

    await expect(
      resolveOAuthUser(provider, {
        subject: 'provider-user',
        email: 'person@example.com',
        raw: {},
      }),
    ).resolves.toBe(emailUser);
  });

  it('does not create a new user when signup is disabled', async () => {
    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(null);

    await expect(
      resolveOAuthUser(
        { ...provider, allowSignup: false },
        { subject: 'provider-user', email: 'new@example.com', raw: {} },
      ),
    ).resolves.toBeNull();

    expect(User.create).not.toHaveBeenCalled();
  });

  it('creates a signup user with default roles and verified email fallbacks', async () => {
    const created = buildUser({ id: 'user-11', email: 'signup@example.com' });

    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({
        login_methods: ['passkey', 'oauth'],
        oauth_providers: [provider],
        default_roles: undefined,
      }),
    );
    (OAuthIdentity.findOne as any).mockResolvedValue(null);
    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockResolvedValue(created);
    (OAuthIdentity.findOrCreate as any).mockResolvedValue([]);

    await expect(
      resolveOAuthUser(provider, {
        subject: 'provider-user',
        email: 'signup@example.com',
        raw: {},
      }),
    ).resolves.toBe(created);

    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({ roles: [], emailVerified: true }),
    );
    expect(OAuthIdentity.findOrCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        defaults: expect.objectContaining({
          profile: { email: 'signup@example.com', name: null },
        }),
      }),
    );
  });
});
