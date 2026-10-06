/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { createRemoteJWKSet, type JWTPayload, jwtVerify } from 'jose';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { withOwnerAdminRole } from '../lib/ownerAdmin.js';
import { allowedRedirect } from '../lib/redirectAllowlist.js';
import { OAuthIdentity } from '../models/oauthIdentities.js';
import { UserExternalId } from '../models/userExternalIds.js';
import { User } from '../models/users.js';
import type { OAuthProviderConfig } from '../schemas/systemConfig.schema.js';
import getLogger from '../utils/logger.js';
import { findOrganizationsRetiringOAuthProvider } from './organizationService.js';

const logger = getLogger('oauthService');

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
  /** Only set from a verified ID token, for a provider that links imported users. */
  externalId?: string;
  name?: string;
  raw: Record<string, unknown>;
};

export type OAuthProfileErrorCode =
  | 'oauth_missing_subject'
  | 'oauth_missing_email'
  | 'oauth_email_not_verified'
  | 'oauth_invalid_id_token';

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

export class OAuthProviderRetiredError extends Error {
  readonly code = 'oauth_provider_retired';
  readonly userId: string;
  readonly organizationIds: string[];

  constructor(userId: string, organizationIds: string[]) {
    super('This sign-in method has been retired for your organization');
    this.name = 'OAuthProviderRetiredError';
    this.userId = userId;
    this.organizationIds = organizationIds;
  }
}

async function assertProviderNotRetired(provider: OAuthProviderConfig, user: User) {
  const retiring = await findOrganizationsRetiringOAuthProvider(user.id, provider.id);

  if (retiring.length > 0) {
    throw new OAuthProviderRetiredError(
      user.id,
      retiring.map((organization) => organization.id),
    );
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

/**
 * The signed state, and the payload that went into it.
 *
 * Both, because the caller needs the nonce and the rest of the payload to build the
 * authorization URL. Returning only the string meant verifying it back immediately:
 * a second HMAC, a decode, a parse and a re-check of fields the caller had just set.
 */
export function createOAuthState(payload: Omit<OAuthStatePayload, 'createdAt' | 'nonce'>): {
  state: string;
  payload: OAuthStatePayload;
} {
  const statePayload: OAuthStatePayload = {
    ...payload,
    nonce: randomBytes(16).toString('base64url'),
    createdAt: Date.now(),
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(statePayload));
  const signature = signPayload(encodedPayload);

  return { state: `${encodedPayload}.${signature}`, payload: statePayload };
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

  if (nonce && (provider.scopes.includes('openid') || isOidcProvider(provider))) {
    url.searchParams.set('nonce', nonce);
  }

  if (codeChallenge) {
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
  }

  return url.toString();
}

export async function exchangeOAuthCode(args: {
  provider: OAuthProviderConfig;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
}) {
  return (await exchangeOAuthTokens(args)).accessToken;
}

export async function exchangeOAuthTokens({
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

  const idToken = tokenResponse.id_token;

  return {
    accessToken,
    ...(typeof idToken === 'string' && idToken ? { idToken } : {}),
  };
}

/** A provider configured for OpenID Connect: its profile comes from a verified ID token. */
export function isOidcProvider(provider: OAuthProviderConfig) {
  return Boolean(provider.issuer || provider.jwksUri);
}

const jwksByUri = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function remoteJwks(uri: string) {
  let jwks = jwksByUri.get(uri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(uri));
    jwksByUri.set(uri, jwks);
  }
  return jwks;
}

// Asymmetric only. A symmetric algorithm would verify against a key the provider
// shares with every client, and `none` verifies nothing.
const ID_TOKEN_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
];

/**
 * Verifies an OpenID Connect ID token and returns its claims: signature against the
 * provider's published keys, issuer, audience (this client), expiry, and the nonce
 * bound into the signed OAuth state, so a token issued for another sign-in cannot be
 * replayed into this one.
 */
export async function verifyOAuthIdToken(
  provider: OAuthProviderConfig,
  idToken: string | undefined,
  nonce: string,
): Promise<JWTPayload> {
  if (!provider.issuer || !provider.jwksUri) {
    throw new Error('OpenID Connect provider needs both issuer and jwksUri');
  }
  if (!idToken) {
    throw new OAuthProfileError('oauth_invalid_id_token', 'OAuth token response had no ID token');
  }

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(idToken, remoteJwks(provider.jwksUri), {
      issuer: provider.issuer,
      audience: provider.clientId,
      algorithms: ID_TOKEN_ALGORITHMS,
      clockTolerance: 60,
      requiredClaims: ['exp', 'iat', 'sub'],
    }));
  } catch (error) {
    logger.warn(`OAuth ID token from ${provider.id} failed verification: ${error}`);
    throw new OAuthProfileError('oauth_invalid_id_token', 'OAuth ID token could not be verified');
  }

  // OpenID Connect Core 3.1.3.7: with more than one audience, the authorized party
  // has to be this client.
  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== provider.clientId) {
    throw new OAuthProfileError('oauth_invalid_id_token', 'OAuth ID token could not be verified');
  }

  if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, nonce)) {
    throw new OAuthProfileError('oauth_invalid_id_token', 'OAuth ID token nonce does not match');
  }

  return payload;
}

/** The profile carried by a verified ID token, including the imported-user link claim. */
export function oauthProfileFromIdToken(
  provider: OAuthProviderConfig,
  claims: JWTPayload,
): OAuthProfile {
  const raw = claims as Record<string, unknown>;
  const profile = parseOAuthProfile(provider, raw);

  if (provider.externalIdSource && provider.externalIdJsonPath) {
    const externalId = getJsonPathValue(raw, provider.externalIdJsonPath);
    if (typeof externalId === 'string' || typeof externalId === 'number') {
      return { ...profile, externalId: String(externalId) };
    }
  }

  return profile;
}

/**
 * GitHub's `/user` reports the public profile email, which may be absent and never
 * says whether it is verified. The verification status lives at `/user/emails`
 * (scope `user:email`), so a GitHub provider is recognised by its userinfo endpoint
 * and asked there. Covers github.com and GitHub Enterprise Server (`/api/v3/user`).
 */
function githubEmailsUrl(provider: OAuthProviderConfig): string | null {
  let url: URL;
  try {
    url = new URL(provider.userInfoUrl);
  } catch {
    return null;
  }

  const path = url.pathname.replace(/\/+$/, '');
  const isGitHub =
    (url.hostname === 'api.github.com' && path === '/user') || path.endsWith('/api/v3/user');

  return isGitHub ? `${url.origin}${path}/emails` : null;
}

type GitHubEmail = { email?: unknown; primary?: unknown; verified?: unknown };

/**
 * The verified address GitHub vouches for: the profile's own email when GitHub lists
 * it as verified, otherwise the primary verified one. Null when there is none, or the
 * list could not be read (for example the token lacks `user:email`), which leaves the
 * profile unverified rather than failing the sign-in outright.
 */
async function fetchGitHubVerifiedEmail(
  emailsUrl: string,
  accessToken: string,
  profileEmail: string | null,
): Promise<string | null> {
  const response = await globalThis.fetch(emailsUrl, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    logger.warn(`GitHub email list fetch failed with status ${response.status}`);
    return null;
  }

  const list = (await response.json()) as unknown;
  if (!Array.isArray(list)) return null;

  const verified = (list as GitHubEmail[]).filter(
    (entry) => entry.verified === true && typeof entry.email === 'string',
  );
  const match = (candidate: GitHubEmail) => normalizeEmail(candidate.email);

  return (
    (profileEmail && verified.map(match).find((email) => email === profileEmail)) ||
    verified.filter((entry) => entry.primary === true).map(match)[0] ||
    null
  );
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
  let email = normalizeEmail(getJsonPathValue(raw, provider.emailJsonPath));
  let emailVerifiedValue = getJsonPathValue(raw, provider.emailVerifiedJsonPath);

  const emailsUrl = githubEmailsUrl(provider);
  if (emailsUrl) {
    const verifiedEmail = await fetchGitHubVerifiedEmail(emailsUrl, accessToken, email);
    if (verifiedEmail) {
      email = verifiedEmail;
      emailVerifiedValue = true;
    }
  }

  return parseOAuthProfile(provider, raw, { email, emailVerifiedValue });
}

function parseOAuthProfile(
  provider: OAuthProviderConfig,
  raw: Record<string, unknown>,
  overrides: { email?: string | null; emailVerifiedValue?: unknown } = {},
): OAuthProfile {
  const subject = getJsonPathValue(raw, provider.subjectJsonPath);
  const email =
    'email' in overrides
      ? overrides.email
      : normalizeEmail(getJsonPathValue(raw, provider.emailJsonPath));
  const emailVerifiedValue =
    'emailVerifiedValue' in overrides
      ? overrides.emailVerifiedValue
      : getJsonPathValue(raw, provider.emailVerifiedJsonPath);
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

/**
 * Marks an account that had never proven its address as claimed by the person the
 * provider just authenticated. Anyone can create an unverified account from an address
 * alone and verify a phone on it, so a phone verified before this point was proven by
 * someone other than the owner and must not survive as a login factor. An unverified
 * phone (an imported one) is kept.
 */
async function claimUnverifiedAccount(user: User, emailVerified: boolean) {
  if (user.verified) return;

  await user.update({
    verified: true,
    ...(emailVerified ? { emailVerified: true } : {}),
    emailVerificationToken: null,
    emailVerificationTokenExpiry: null,
    phoneVerificationToken: null,
    phoneVerificationTokenExpiry: null,
    phoneVerifiedAttemptId: null,
    ...(user.phoneVerified ? { phone: null, phoneVerified: false } : {}),
  });
}

async function linkOAuthIdentity(provider: OAuthProviderConfig, profile: OAuthProfile, user: User) {
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
    if (user) {
      await assertProviderNotRetired(provider, user);
      return user;
    }
  }

  // A user imported from this provider's own directory is matched on the id the
  // directory gave them, read from a verified ID token, not on an email that directory
  // lets its administrators edit. `externalId` is only ever set from a verified token.
  if (provider.externalIdSource && profile.externalId) {
    const link = await UserExternalId.findOne({
      where: { source: provider.externalIdSource, externalId: profile.externalId },
    });
    const imported = link ? await User.findByPk(link.userId) : null;

    if (imported) {
      // Before claiming or linking, so a refused sign-in leaves the account as it was.
      await assertProviderNotRetired(provider, imported);
      await claimUnverifiedAccount(imported, profile.emailVerified === true);
      await linkOAuthIdentity(provider, profile, imported);
      return imported;
    }
  }

  const emailUser = await User.findOne({ where: { email: profile.email } });
  let user = emailUser;

  if (emailUser && provider.accountLinking === 'disabled') {
    return null;
  }

  if (!user && !provider.allowSignup) {
    return null;
  }

  // Past this point the email decides whose account this is, either by linking to the
  // one that holds it or by creating one for it. A provider that does not assert the
  // address is verified may be reporting a value its own tenant administrator set, so
  // trusting it would hand over the account (or the owner grant) to whoever controls
  // that tenant. `requireEmailVerified` only governed the profile fetch, and defaulted
  // off, so it is not consulted here.
  if (profile.emailVerified !== true) {
    throw new OAuthProfileError('oauth_email_not_verified', 'OAuth profile email is not verified');
  }

  if (user) {
    await assertProviderNotRetired(provider, user);
    await claimUnverifiedAccount(user, true);
  } else {
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
      emailVerified: true,
      phoneVerified: false,
    });
  }

  await linkOAuthIdentity(provider, profile, user);

  return user;
}
