import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { OAuthProviderPolicyError } from '../../../src/lib/oauthProviderPolicy.js';
import {
  clearOAuthDiscoveryCache,
  discoverOAuthEndpoints,
  OAuthDiscoveryError,
} from '../../../src/services/oauthDiscovery.js';

const issuer = 'https://idp.example.com';

function metadata(overrides: Record<string, unknown> = {}) {
  return {
    issuer,
    authorization_endpoint: 'https://idp.example.com/authorize',
    token_endpoint: 'https://idp.example.com/token',
    userinfo_endpoint: 'https://idp.example.com/userinfo',
    jwks_uri: 'https://idp.example.com/jwks',
    ...overrides,
  };
}

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  clearOAuthDiscoveryCache();
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('discoverOAuthEndpoints', () => {
  it('reads the endpoints from the issuer discovery document', async () => {
    fetchMock.mockResolvedValue(jsonResponse(metadata()));

    await expect(discoverOAuthEndpoints(`${issuer}/`)).resolves.toEqual({
      issuer,
      authorizationUrl: 'https://idp.example.com/authorize',
      tokenUrl: 'https://idp.example.com/token',
      userInfoUrl: 'https://idp.example.com/userinfo',
      jwksUri: 'https://idp.example.com/jwks',
    });
    expect(fetchMock.mock.calls[0][0]).toBe(`${issuer}/.well-known/openid-configuration`);
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: 'manual' });
  });

  it('leaves out a userinfo endpoint the document does not publish', async () => {
    fetchMock.mockResolvedValue(jsonResponse(metadata({ userinfo_endpoint: undefined })));

    const endpoints = await discoverOAuthEndpoints(issuer);

    expect(endpoints).not.toHaveProperty('userInfoUrl');
  });

  it('caches a document until asked to refresh', async () => {
    fetchMock.mockImplementation(async () => jsonResponse(metadata()));

    await discoverOAuthEndpoints(issuer);
    await discoverOAuthEndpoints(issuer);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await discoverOAuthEndpoints(issuer, { refresh: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('fetches again once the cached document expires', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(async () => jsonResponse(metadata()));

    await discoverOAuthEndpoints(issuer);
    vi.advanceTimersByTime(60 * 60 * 1000 + 1);
    await discoverOAuthEndpoints(issuer);

    vi.useRealTimers();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('starts the cache over once it holds the most issuers it keeps', async () => {
    fetchMock.mockImplementation(async (url: string) =>
      jsonResponse(metadata({ issuer: url.replace('/.well-known/openid-configuration', '') })),
    );

    for (let index = 0; index <= 100; index += 1) {
      await discoverOAuthEndpoints(`https://idp${index}.example.com`);
    }
    await discoverOAuthEndpoints('https://idp0.example.com');

    expect(fetchMock).toHaveBeenCalledTimes(102);
  });

  it('refuses a document that names another issuer', async () => {
    fetchMock.mockResolvedValue(jsonResponse(metadata({ issuer: 'https://evil.example.com' })));

    await expect(discoverOAuthEndpoints(issuer)).rejects.toThrow(
      new OAuthDiscoveryError('OpenID discovery document names a different issuer'),
    );
  });

  it('refuses a document missing a required endpoint', async () => {
    fetchMock.mockResolvedValue(jsonResponse(metadata({ jwks_uri: undefined })));

    await expect(discoverOAuthEndpoints(issuer)).rejects.toThrow(/missing required endpoints/);
  });

  it('refuses a body that is not JSON', async () => {
    fetchMock.mockResolvedValue(jsonResponse('<html>'));

    await expect(discoverOAuthEndpoints(issuer)).rejects.toThrow(/is not JSON/);
  });

  it('refuses a failed response', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}, { status: 404 }));

    await expect(discoverOAuthEndpoints(issuer)).rejects.toThrow(/status 404/);
  });

  it('refuses a document declared larger than the cap', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(metadata(), { headers: { 'content-length': String(64 * 1024 + 1) } }),
    );

    await expect(discoverOAuthEndpoints(issuer)).rejects.toThrow(/too large/);
  });

  it('refuses a document larger than the cap that did not declare its length', async () => {
    fetchMock.mockResolvedValue(jsonResponse(metadata({ padding: 'x'.repeat(64 * 1024) })));

    await expect(discoverOAuthEndpoints(issuer)).rejects.toThrow(/too large/);
  });

  it('does not follow a redirect', async () => {
    fetchMock.mockResolvedValue(
      new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/' } }),
    );

    await expect(discoverOAuthEndpoints(issuer)).rejects.toBeInstanceOf(OAuthProviderPolicyError);
  });

  it('refuses an http issuer in production', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    await expect(discoverOAuthEndpoints('http://idp.example.com')).rejects.toBeInstanceOf(
      OAuthProviderPolicyError,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a loopback issuer in production', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    await expect(discoverOAuthEndpoints('https://127.0.0.1')).rejects.toBeInstanceOf(
      OAuthProviderPolicyError,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
