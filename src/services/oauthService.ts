/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { withOwnerAdminRole } from '../lib/ownerAdmin.js';
import { OAuthIdentity } from '../models/oauthIdentities.js';
import { User } from '../models/users.js';
import type { OAuthProviderConfig } from '../schemas/systemConfig.schema.js';

const STATE_TTL_MS = 10 * 60 * 1000;
const consumedStateHashes = new Map<string, number>();

export type PublicOAuthProvider = {
  id: string;
  name: string;
  scopes: string[];
};

export type OAuthStatePayload = {
  providerId: string;
  redirectUri: string;
  returnTo?: string;
  nonce: string;
  createdAt: number;
};

export type OAuthProfile = {
  subject: string;
  email: string;
  emailVerified?: boolean;
  name?: string;
  raw: Record<string, unknown>;
};

export type OAuthProfileErrorCode =
  | 'oauth_missing_subject'
  | 'oauth_missing_email'
  | 'oauth_email_not_verified';

// Curated, user-actionable profile failures. The controller forwards the code
// to the caller; every other failure stays a bare Error and returns generic.
export class OAuthProfileError extends Error {
  readonly code: OAuthProfileErrorCode;

  constructor(code: OAuthProfileErrorCode, message: string) {
    super(message);
    this.name = 'OAuthProfileError';
    this.code = code;
  }
}

function stateSecret() {
  const explicit = process.env.OAUTH_STATE_SECRET?.trim();
  if (explicit) return explicit;

  const serviceSecret = process.env.API_SERVICE_TOKEN?.trim();
  if (serviceSecret) return serviceSecret;

  if (process.env.NODE_ENV !== 'production') {
    return `dev-oauth-state:${process.env.APP_ID ?? 'local'}`;
  }

  throw new Error('OAUTH_STATE_SECRET or API_SERVICE_TOKEN is required in production.');
}

function base64UrlEncode(value: string) {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function signPayload(payload: string) {
  return createHmac('sha256', stateSecret()).update(payload).digest('base64url');
}

function hashStateForReplayCache(state: string) {
  return createHmac('sha256', stateSecret()).update(`oauth-state:${state}`).digest('base64url');
}

function purgeConsumedStates(now = Date.now()) {
  for (const [stateHash, expiresAt] of consumedStateHashes.entries()) {
    if (expiresAt <= now) {
      consumedStateHashes.delete(stateHash);
    }
  }
}

function pkceEnabled(provider: OAuthProviderConfig) {
  return provider.pkce !== false;
}

function sha256Base64Url(value: string) {
  return createHash('sha256').update(value).digest('base64url');
}

function safeEqual(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);

  if (left.length !== right.length) return false;

  return timingSafeEqual(left, right);
}

function getJsonPathValue(input: Record<string, unknown>, path?: string) {
  if (!path) return undefined;

  return path.split('.').reduce<unknown>((current, segment) => {
    if (!current || typeof current !== 'object') return undefined;
    return (current as Record<string, unknown>)[segment];
  }, input);
}

function normalizeEmail(value: unknown) {
  return typeof value === 'string' && value.includes('@') ? value.toLowerCase() : null;
}

function parseUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function sameOrigin(value: string, allowedOrigin: string) {
  const parsedValue = parseUrl(value);
  const parsedAllowedOrigin = parseUrl(allowedOrigin);

  if (!parsedValue || !parsedAllowedOrigin) return false;

  return parsedValue.origin === parsedAllowedOrigin.origin;
}

function allowedRedirect(value: string, allowedValues: string[], fallbackOrigins: string[]) {
  const parsedValue = parseUrl(value);
  if (!parsedValue) return false;

  if (allowedValues.length > 0) {
    return allowedValues.some((allowedValue) => value === allowedValue);
  }

  return fallbackOrigins.some((origin) => sameOrigin(value, origin));
}

function providerRedirectAllowlist(provider: OAuthProviderConfig) {
  return Array.from(
    new Set([
      ...(provider.redirectUris ?? []),
      ...(provider.redirectUri ? [provider.redirectUri] : []),
    ]),
  );
}

export async function getEnabledOAuthProviders() {
  const config = await getSystemConfig();

  if (!config.login_methods.includes('oauth')) {
    return [];
  }

  return config.oauth_providers.filter((provider) => provider.enabled);
}

export function serializeOAuthProvider(provider: OAuthProviderConfig): PublicOAuthProvider {
  return {
    id: provider.id,
    name: provider.name,
    scopes: provider.scopes ?? [],
  };
}

export async function getOAuthProvider(providerId: string) {
  const providers = await getEnabledOAuthProviders();
  return providers.find((provider) => provider.id === providerId) ?? null;
}

export async function resolveOAuthRedirectUri(
  provider: OAuthProviderConfig,
  requestedRedirectUri?: string,
) {
  const config = await getSystemConfig();
  const providerAllowlist = providerRedirectAllowlist(provider);

  if (requestedRedirectUri) {
    if (!allowedRedirect(requestedRedirectUri, providerAllowlist, config.origins)) {
      throw new Error('OAuth redirect URI is not allowed');
    }

    return requestedRedirectUri;
  }

  if (provider.redirectUri) {
    return provider.redirectUri;
  }

  return `${config.origins[0].replace(/\/$/, '')}/oauth/callback`;
}

export function createOAuthState(payload: Omit<OAuthStatePayload, 'createdAt' | 'nonce'>) {
  const statePayload: OAuthStatePayload = {
    ...payload,
    nonce: randomBytes(16).toString('base64url'),
    createdAt: Date.now(),
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(statePayload));
  const signature = signPayload(encodedPayload);

  return `${encodedPayload}.${signature}`;
}

export function verifyOAuthState(state: string, providerId: string): OAuthStatePayload | null {
  const [encodedPayload, signature] = state.split('.');

  if (!encodedPayload || !signature) return null;
  if (!safeEqual(signPayload(encodedPayload), signature)) return null;

  let payload: OAuthStatePayload;

  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload)) as OAuthStatePayload;
  } catch {
    return null;
  }

  if (payload.providerId !== providerId) return null;
  if (typeof payload.redirectUri !== 'string') return null;
  if (typeof payload.createdAt !== 'number') return null;
  if (Date.now() - payload.createdAt > STATE_TTL_MS) return null;

  return payload;
}

export function consumeOAuthState(state: string, providerId: string): OAuthStatePayload | null {
  const payload = verifyOAuthState(state, providerId);

  if (!payload) return null;

  purgeConsumedStates();

  const stateHash = hashStateForReplayCache(state);

  if (consumedStateHashes.has(stateHash)) {
    return null;
  }

  consumedStateHashes.set(stateHash, payload.createdAt + STATE_TTL_MS);

  return payload;
}

export function clearOAuthStateReplayCache() {
  consumedStateHashes.clear();
}

export function createOAuthPkceCodeVerifier(
  provider: OAuthProviderConfig,
  payload: OAuthStatePayload,
) {
  if (!pkceEnabled(provider)) return undefined;

  return createHmac('sha256', stateSecret())
    .update(
      JSON.stringify([
        'oauth-pkce-v1',
        provider.id,
        payload.providerId,
        payload.redirectUri,
        payload.nonce,
        payload.createdAt,
      ]),
    )
    .digest('base64url');
}

export function createOAuthPkceCodeChallenge(
  provider: OAuthProviderConfig,
  payload: OAuthStatePayload,
) {
  const verifier = createOAuthPkceCodeVerifier(provider, payload);

  return verifier ? sha256Base64Url(verifier) : undefined;
}

export function buildOAuthAuthorizationUrl({
  provider,
  redirectUri,
  state,
  nonce,
  codeChallenge,
}: {
  provider: OAuthProviderConfig;
  redirectUri: string;
  state: string;
  nonce?: string;
  codeChallenge?: string;
}) {
  const url = new URL(provider.authorizationUrl);

  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', provider.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('state', state);

  if (provider.scopes.length) {
    url.searchParams.set('scope', provider.scopes.join(' '));
  }

  if (nonce && provider.scopes.includes('openid')) {
    url.searchParams.set('nonce', nonce);
  }

  if (codeChallenge) {
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
  }

  return url.toString();
}

export async function exchangeOAuthCode({
  provider,
  code,
  redirectUri,
  codeVerifier,
}: {
  provider: OAuthProviderConfig;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
}) {
  const clientSecret = process.env[provider.clientSecretEnv];

  if (!clientSecret) {
    throw new Error(`OAuth client secret env "${provider.clientSecretEnv}" is not configured`);
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: provider.clientId,
    client_secret: clientSecret,
  });

  if (codeVerifier) {
    body.set('code_verifier', codeVerifier);
  }

  const response = await globalThis.fetch(provider.tokenUrl, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  if (!response.ok) {
    throw new Error(`OAuth token exchange failed with status ${response.status}`);
  }

  const tokenResponse = (await response.json()) as Record<string, unknown>;
  const accessToken = tokenResponse.access_token;

  if (typeof accessToken !== 'string' || !accessToken) {
    throw new Error('OAuth token response did not include an access token');
  }

  return accessToken;
}

export async function fetchOAuthProfile(provider: OAuthProviderConfig, accessToken: string) {
  const response = await globalThis.fetch(provider.userInfoUrl, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`OAuth profile fetch failed with status ${response.status}`);
  }

  const raw = (await response.json()) as Record<string, unknown>;
  const subject = getJsonPathValue(raw, provider.subjectJsonPath);
  const email = normalizeEmail(getJsonPathValue(raw, provider.emailJsonPath));
  const emailVerifiedValue = getJsonPathValue(raw, provider.emailVerifiedJsonPath);
  const name = getJsonPathValue(raw, provider.nameJsonPath);

  if (typeof subject !== 'string' && typeof subject !== 'number') {
    throw new OAuthProfileError(
      'oauth_missing_subject',
      'OAuth profile did not include a provider subject',
    );
  }

  if (!email) {
    throw new OAuthProfileError(
      'oauth_missing_email',
      'OAuth profile did not include an email address',
    );
  }

  const emailVerified =
    typeof emailVerifiedValue === 'boolean'
      ? emailVerifiedValue
      : typeof emailVerifiedValue === 'string'
        ? emailVerifiedValue.toLowerCase() === 'true'
        : undefined;

  if (emailVerified === false || (provider.requireEmailVerified && emailVerified !== true)) {
    throw new OAuthProfileError('oauth_email_not_verified', 'OAuth profile email is not verified');
  }

  return {
    subject: String(subject),
    email,
    ...(emailVerified === undefined ? {} : { emailVerified }),
    ...(typeof name === 'string' ? { name } : {}),
    raw,
  } satisfies OAuthProfile;
}

export async function resolveOAuthUser(provider: OAuthProviderConfig, profile: OAuthProfile) {
  const existingIdentity = await OAuthIdentity.findOne({
    where: {
      providerId: provider.id,
      providerSubject: profile.subject,
    },
  });

  if (existingIdentity) {
    const user = await User.findByPk(existingIdentity.userId);
    if (user) return user;
  }

  const emailUser = await User.findOne({ where: { email: profile.email } });
  let user = emailUser;

  if (emailUser && provider.accountLinking === 'disabled') {
    return null;
  }

  if (!user) {
    if (!provider.allowSignup) {
      return null;
    }

    const config = await getSystemConfig();

    user = await User.create({
      email: profile.email,
      phone: null,
      roles: withOwnerAdminRole(
        config.default_roles ?? [],
        profile.email,
        config.available_roles ?? [],
      ),
      verified: true,
      emailVerified: profile.emailVerified ?? true,
      phoneVerified: false,
    });
  }

  await OAuthIdentity.findOrCreate({
    where: {
      providerId: provider.id,
      providerSubject: profile.subject,
    },
    defaults: {
      userId: user.id,
      providerId: provider.id,
      providerSubject: profile.subject,
      email: profile.email,
      profile: {
        email: profile.email,
        name: profile.name ?? null,
      },
    },
  });

  return user;
}
