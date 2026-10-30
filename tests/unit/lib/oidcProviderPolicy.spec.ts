import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/services/oidcProviderKeys', () => ({
  hasOidcProviderKeys: vi.fn(),
  sharesFirstPartyKey: vi.fn(() => false),
}));

import { oidcProviderConfigProblems } from '../../../src/lib/oidcProviderPolicy';
import { hasOidcProviderKeys, sharesFirstPartyKey } from '../../../src/services/oidcProviderKeys';

const env = { NODE_ENV: 'production', ISSUER: 'https://auth.example.com' };

function problems(overrides: Record<string, unknown>, source: Record<string, string> = env) {
  return oidcProviderConfigProblems(
    { oidc_provider_enabled: false, oidc_issuer: null, rpid: 'example.com', ...overrides },
    source,
  );
}

describe('oidcProviderConfigProblems', () => {
  it('has nothing to say about a disabled provider with no issuer', () => {
    expect(problems({})).toEqual([]);
  });

  it('accepts an https issuer under rpid with keys present', () => {
    vi.mocked(hasOidcProviderKeys).mockReturnValue(true);

    expect(
      problems({ oidc_provider_enabled: true, oidc_issuer: 'https://login.example.com' }),
    ).toEqual([]);
    expect(problems({ oidc_issuer: 'https://example.com' })).toEqual([]);
  });

  it('refuses plain http outside local development', () => {
    expect(problems({ oidc_issuer: 'http://login.example.com' })).toContain(
      'oidc_issuer must use https',
    );
    expect(
      problems(
        { oidc_issuer: 'http://localhost:5400', rpid: 'localhost' },
        { NODE_ENV: 'production' },
      ),
    ).toContain('oidc_issuer must use https');
    expect(
      problems(
        { oidc_issuer: 'http://localhost:5400', rpid: 'localhost' },
        { NODE_ENV: 'development' },
      ),
    ).toEqual([]);
  });

  it('refuses a query or fragment', () => {
    expect(problems({ oidc_issuer: 'https://login.example.com/?a=1' })).toContain(
      'oidc_issuer must not have a query or fragment',
    );
    expect(problems({ oidc_issuer: 'https://login.example.com/#a' })).toContain(
      'oidc_issuer must not have a query or fragment',
    );
  });

  it('refuses the API issuer, trailing slash or not', () => {
    expect(problems({ oidc_issuer: 'https://auth.example.com/' })).toContain(
      'oidc_issuer must differ from the API ISSUER',
    );
  });

  it('refuses a host rpid does not cover', () => {
    expect(problems({ oidc_issuer: 'https://login.example.org' })).toContain(
      'oidc_issuer host login.example.org is not covered by rpid example.com',
    );
    expect(problems({ oidc_issuer: 'https://badexample.com' })[0]).toMatch(/not covered/);
  });

  it('refuses to enable without an issuer or keys', () => {
    vi.mocked(hasOidcProviderKeys).mockReturnValue(false);

    expect(problems({ oidc_provider_enabled: true })).toEqual([
      'oidc_provider_enabled needs oidc_issuer',
      'oidc_provider_enabled needs OIDC_JWKS_ACTIVE_KID and OIDC_JWKS_KEYS',
    ]);
  });

  it('refuses provider keys that reuse a first-party key', () => {
    vi.mocked(hasOidcProviderKeys).mockReturnValue(true);
    vi.mocked(sharesFirstPartyKey).mockReturnValue(true);

    expect(
      problems({ oidc_provider_enabled: true, oidc_issuer: 'https://login.example.com' }),
    ).toEqual(['OIDC_JWKS_KEYS must not reuse a SEAMLESS_JWKS signing key']);
  });

  it('reads the process environment by default', () => {
    expect(
      oidcProviderConfigProblems({
        oidc_provider_enabled: false,
        oidc_issuer: null,
        rpid: 'example.com',
      }),
    ).toEqual([]);
  });
});
