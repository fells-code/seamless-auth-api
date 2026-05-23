/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { OAuthIdentity } from '../models/oauthIdentities.js';
import { User } from '../models/users.js';
import type { OAuthProviderConfig } from '../schemas/systemConfig.schema.js';

const STATE_TTL_MS = 10 * 60 * 1000;

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
  name?: string;
  raw: Record<string, unknown>;
};

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

function allowedRedirect(value: string, origins: string[]) {
  return origins.some((origin) => value.startsWith(origin));
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

  if (requestedRedirectUri) {
    if (!allowedRedirect(requestedRedirectUri, config.origins)) {
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

  const payload = JSON.parse(base64UrlDecode(encodedPayload)) as OAuthStatePayload;

  if (payload.providerId !== providerId) return null;
  if (Date.now() - payload.createdAt > STATE_TTL_MS) return null;

  return payload;
}

export function buildOAuthAuthorizationUrl({
  provider,
  redirectUri,
  state,
}: {
  provider: OAuthProviderConfig;
  redirectUri: string;
  state: string;
}) {
  const url = new URL(provider.authorizationUrl);

  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', provider.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('state', state);

  if (provider.scopes.length) {
    url.searchParams.set('scope', provider.scopes.join(' '));
  }

  return url.toString();
}

export async function exchangeOAuthCode({
  provider,
  code,
  redirectUri,
}: {
  provider: OAuthProviderConfig;
  code: string;
  redirectUri: string;
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
  const name = getJsonPathValue(raw, provider.nameJsonPath);

  if (typeof subject !== 'string' && typeof subject !== 'number') {
    throw new Error('OAuth profile did not include a provider subject');
  }

  if (!email) {
    throw new Error('OAuth profile did not include an email address');
  }

  return {
    subject: String(subject),
    email,
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

  let user = await User.findOne({ where: { email: profile.email } });

  if (!user) {
    if (!provider.allowSignup) {
      return null;
    }

    const config = await getSystemConfig();

    user = await User.create({
      email: profile.email,
      phone: `oauth:${provider.id}:${profile.subject}`.slice(0, 255),
      roles: config.default_roles ?? [],
      verified: true,
      emailVerified: true,
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
