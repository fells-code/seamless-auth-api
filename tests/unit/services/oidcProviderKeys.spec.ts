import { generateKeyPairSync, KeyObject } from 'crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  __resetOidcProviderKeyCache,
  getActiveOidcSigningKey,
  getOidcPublicJwks,
  hasOidcProviderKeys,
  OidcProviderKeysError,
} from '../../../src/services/oidcProviderKeys';

function privateJwk(kid: string) {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { ...privateKey.export({ format: 'jwk' }), kid };
}

const k1 = privateJwk('k1');
const k2 = privateJwk('k2');

function env(activeKid: string | undefined, keys: unknown) {
  return {
    OIDC_JWKS_ACTIVE_KID: activeKid,
    OIDC_JWKS_KEYS: typeof keys === 'string' ? keys : JSON.stringify(keys),
  };
}

describe('oidcProviderKeys', () => {
  beforeEach(() => {
    __resetOidcProviderKeyCache();
  });

  it('publishes public members only, active key first', () => {
    vi.stubEnv('OIDC_JWKS_ACTIVE_KID', 'k2');
    vi.stubEnv('OIDC_JWKS_KEYS', JSON.stringify({ keys: [k1, k2] }));

    const jwks = getOidcPublicJwks();

    expect(jwks.activeKid).toBe('k2');
    expect(jwks.keys.map((key) => key.kid)).toEqual(['k2', 'k1']);
    for (const key of jwks.keys) {
      expect(key).toEqual({
        kty: 'RSA',
        kid: key.kid,
        alg: 'RS256',
        use: 'sig',
        n: expect.any(String),
        e: 'AQAB',
      });
    }
  });

  it('keeps the active key first whichever way the sort compares', () => {
    vi.stubEnv('OIDC_JWKS_ACTIVE_KID', 'k1');
    vi.stubEnv('OIDC_JWKS_KEYS', JSON.stringify({ keys: [k2, privateJwk('k3'), k1] }));

    expect(getOidcPublicJwks().keys[0].kid).toBe('k1');
  });

  it('signs only with the active key', () => {
    vi.stubEnv('OIDC_JWKS_ACTIVE_KID', 'k1');
    vi.stubEnv('OIDC_JWKS_KEYS', JSON.stringify({ keys: [k1, k2] }));

    expect(getActiveOidcSigningKey('k1')).toBeInstanceOf(KeyObject);
    expect(getActiveOidcSigningKey('k2')).toBeNull();
  });

  it('caches the key set', () => {
    vi.stubEnv('OIDC_JWKS_ACTIVE_KID', 'k1');
    vi.stubEnv('OIDC_JWKS_KEYS', JSON.stringify({ keys: [k1] }));
    getOidcPublicJwks();

    vi.stubEnv('OIDC_JWKS_KEYS', 'broken');
    expect(getOidcPublicJwks().activeKid).toBe('k1');
  });

  it('throws when the keys are not configured', () => {
    vi.stubEnv('OIDC_JWKS_ACTIVE_KID', '');
    expect(() => getOidcPublicJwks()).toThrow(OidcProviderKeysError);
  });

  it.each([
    ['missing env', env(undefined, { keys: [k1] })],
    ['invalid JSON', env('k1', '{')],
    ['an empty set', env('k1', { keys: [] })],
    ['no keys member', env('k1', {})],
    ['a key without a kid', env('k1', { keys: [{ ...k1, kid: undefined }] })],
    ['duplicate kids', env('k1', { keys: [k1, k1] })],
    ['a public key', env('k1', { keys: [{ ...k1, d: undefined }] })],
    ['a non-RSA key', env('k1', { keys: [{ kty: 'EC', kid: 'k1', d: 'x' }] })],
    ['an active kid not in the set', env('k9', { keys: [k1] })],
  ])('reports %s as unusable', (_label, source) => {
    expect(hasOidcProviderKeys(source)).toBe(false);
  });

  it('reports a good set as usable', () => {
    expect(hasOidcProviderKeys(env('k1', { keys: [k1] }))).toBe(true);
  });
});
