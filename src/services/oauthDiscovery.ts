/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { providerFetch } from '../lib/oauthProviderPolicy.js';

const DISCOVERY_PATH = '/.well-known/openid-configuration';
const DISCOVERY_TIMEOUT_MS = 5_000;
const MAX_DISCOVERY_BYTES = 64 * 1024;
const DISCOVERY_TTL_MS = 60 * 60 * 1000;
const MAX_CACHED_ISSUERS = 100;

export class OAuthDiscoveryError extends Error {}

export type DiscoveredOAuthEndpoints = {
  issuer: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl?: string;
  jwksUri: string;
};

const MetadataSchema = z.object({
  issuer: z.string().min(1),
  authorization_endpoint: z.url(),
  token_endpoint: z.url(),
  userinfo_endpoint: z.url().optional(),
  jwks_uri: z.url(),
});

const cache = new Map<string, { endpoints: DiscoveredOAuthEndpoints; expiresAt: number }>();

function withoutTrailingSlash(value: string) {
  return value.replace(/\/+$/, '');
}

async function readBounded(response: Response) {
  const declared = Number(response.headers.get('content-length'));
  if (declared > MAX_DISCOVERY_BYTES) {
    throw new OAuthDiscoveryError('OpenID discovery document is too large');
  }

  const text = await response.text();
  if (Buffer.byteLength(text) > MAX_DISCOVERY_BYTES) {
    throw new OAuthDiscoveryError('OpenID discovery document is too large');
  }

  return text;
}

async function fetchMetadata(issuer: string): Promise<DiscoveredOAuthEndpoints> {
  const response = await providerFetch(`${withoutTrailingSlash(issuer)}${DISCOVERY_PATH}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new OAuthDiscoveryError(`OpenID discovery failed with status ${response.status}`);
  }

  let body: unknown;
  try {
    body = JSON.parse(await readBounded(response));
  } catch (error) {
    if (error instanceof OAuthDiscoveryError) throw error;
    throw new OAuthDiscoveryError('OpenID discovery document is not JSON');
  }

  const parsed = MetadataSchema.safeParse(body);
  if (!parsed.success) {
    throw new OAuthDiscoveryError('OpenID discovery document is missing required endpoints');
  }

  // OpenID Connect Discovery 4.3: a document naming another issuer is refused, or an
  // issuer could hand out a second provider's endpoints and keys. Only a trailing slash
  // is forgiven, and the document's own spelling is kept since ID tokens carry it.
  if (withoutTrailingSlash(parsed.data.issuer) !== withoutTrailingSlash(issuer)) {
    throw new OAuthDiscoveryError('OpenID discovery document names a different issuer');
  }

  return {
    issuer: parsed.data.issuer,
    authorizationUrl: parsed.data.authorization_endpoint,
    tokenUrl: parsed.data.token_endpoint,
    ...(parsed.data.userinfo_endpoint ? { userInfoUrl: parsed.data.userinfo_endpoint } : {}),
    jwksUri: parsed.data.jwks_uri,
  };
}

/**
 * The endpoints an issuer publishes in its OpenID discovery document. The fetch goes
 * through `providerFetch`, so it gets the same https, non-public address and redirect
 * rules as every other provider call. `refresh` skips the cache.
 */
export async function discoverOAuthEndpoints(
  issuer: string,
  { refresh = false }: { refresh?: boolean } = {},
): Promise<DiscoveredOAuthEndpoints> {
  const key = withoutTrailingSlash(issuer);
  const cached = cache.get(key);

  if (!refresh && cached && cached.expiresAt > Date.now()) {
    return cached.endpoints;
  }

  const endpoints = await fetchMetadata(issuer);

  if (cache.size >= MAX_CACHED_ISSUERS) cache.clear();
  cache.set(key, { endpoints, expiresAt: Date.now() + DISCOVERY_TTL_MS });

  return endpoints;
}

export function clearOAuthDiscoveryCache() {
  cache.clear();
}
