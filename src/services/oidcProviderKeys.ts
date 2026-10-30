/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { OidcPublicJwk } from '@seamless-auth/types';
import { createPrivateKey, createPublicKey, KeyObject } from 'crypto';

import getLogger from '../utils/logger.js';

const logger = getLogger('oidcProviderKeys');

export const OIDC_JWKS_ACTIVE_KID_ENV = 'OIDC_JWKS_ACTIVE_KID';
export const OIDC_JWKS_KEYS_ENV = 'OIDC_JWKS_KEYS';

const CACHE_TTL_MS = 1000 * 60 * 5;

type ProviderKey = { kid: string; privateKey: KeyObject; publicJwk: OidcPublicJwk };

type ProviderKeySet = { activeKid: string; keys: Map<string, ProviderKey>; loadedAt: number };

let cache: ProviderKeySet | null = null;

export function __resetOidcProviderKeyCache() {
  cache = null;
}

export class OidcProviderKeysError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OidcProviderKeysError';
  }
}

/**
 * The provider's own RS256 key set (ADR 0001, D4), kept apart from the first-party
 * `SEAMLESS_JWKS_*` keys so a provider token can never verify as a first-party one. Read
 * straight from the environment rather than through `getSecret`, which logs every miss as
 * an error, because an instance without the provider legitimately has none.
 */
function loadKeySet(env: Record<string, string | undefined>): ProviderKeySet {
  const activeKid = env[OIDC_JWKS_ACTIVE_KID_ENV]?.trim();
  const raw = env[OIDC_JWKS_KEYS_ENV]?.trim();

  if (!activeKid || !raw) {
    throw new OidcProviderKeysError(
      `${OIDC_JWKS_ACTIVE_KID_ENV} and ${OIDC_JWKS_KEYS_ENV} must both be set`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new OidcProviderKeysError(`${OIDC_JWKS_KEYS_ENV} is not valid JSON`);
  }

  const jwks = (parsed as { keys?: unknown }).keys;
  if (!Array.isArray(jwks) || jwks.length === 0) {
    throw new OidcProviderKeysError(
      `${OIDC_JWKS_KEYS_ENV} must be a JWK set with at least one key`,
    );
  }

  const keys = new Map<string, ProviderKey>();

  for (const jwk of jwks as JsonWebKey[]) {
    const kid = (jwk as { kid?: unknown }).kid;

    if (typeof kid !== 'string' || !kid || keys.has(kid)) {
      throw new OidcProviderKeysError('Every provider key needs a unique kid');
    }

    if (jwk.kty !== 'RSA' || !jwk.d) {
      throw new OidcProviderKeysError(`Provider key ${kid} must be a private RSA JWK`);
    }

    const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
    const { kty, n, e } = createPublicKey(privateKey).export({ format: 'jwk' });

    keys.set(kid, {
      kid,
      privateKey,
      publicJwk: { kty: kty as string, kid, alg: 'RS256', use: 'sig', n, e },
    });
  }

  if (!keys.has(activeKid)) {
    throw new OidcProviderKeysError(`${OIDC_JWKS_ACTIVE_KID_ENV} names a key not in the set`);
  }

  return { activeKid, keys, loadedAt: Date.now() };
}

function getKeySet(env: Record<string, string | undefined> = process.env): ProviderKeySet {
  if (cache && Date.now() - cache.loadedAt < CACHE_TTL_MS) {
    return cache;
  }

  cache = loadKeySet(env);
  return cache;
}

function firstPartyModuli(env: Record<string, string | undefined>) {
  try {
    const parsed = JSON.parse(env.SEAMLESS_JWKS_PUBLIC_KEYS ?? '{"keys":[]}') as {
      keys?: { pem?: string }[];
    };
    return new Set(
      (parsed.keys ?? []).flatMap((key) =>
        key.pem ? [createPublicKey(key.pem).export({ format: 'jwk' }).n] : [],
      ),
    );
  } catch {
    return new Set<string | undefined>();
  }
}

/**
 * Whether a provider key is also a first-party signing key. Shared key material would let a
 * provider token verify against the first-party JWKS, which D11 rules out.
 */
export function sharesFirstPartyKey(env: Record<string, string | undefined> = process.env) {
  const firstParty = firstPartyModuli(env);
  const raw = env[OIDC_JWKS_KEYS_ENV];

  try {
    const keys = (JSON.parse(raw ?? '{"keys":[]}') as { keys?: { n?: string }[] }).keys ?? [];
    return keys.some((key) => key.n !== undefined && firstParty.has(key.n));
  } catch {
    return false;
  }
}

/** Whether a usable provider key set is configured. Never throws. */
export function hasOidcProviderKeys(env: Record<string, string | undefined> = process.env) {
  try {
    loadKeySet(env);
    return true;
  } catch (error) {
    logger.warn(`Provider signing keys unusable: ${(error as Error).message}`);
    return false;
  }
}

/** Active key first, so a consumer that picks the first RS256 key picks the one we sign with. */
export function getOidcPublicJwks() {
  const { activeKid, keys } = getKeySet();
  const ordered = [...keys.values()].sort((a, b) =>
    a.kid === activeKid ? -1 : b.kid === activeKid ? 1 : 0,
  );

  return { activeKid, keys: ordered.map((key) => key.publicJwk) };
}

/** Only the active key signs. A published key that is not yet active, or retiring, does not. */
export function getActiveOidcSigningKey(kid: string): KeyObject | null {
  const { activeKid, keys } = getKeySet();

  return kid === activeKid ? (keys.get(kid)?.privateKey ?? null) : null;
}
