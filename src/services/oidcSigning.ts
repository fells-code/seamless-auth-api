/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  CUSTOM_CLAIM_NAME_PATTERN,
  isReservedClaimName,
  type OidcSignRefusalCode,
  type OidcSignRequest,
  seamlessBuiltInResource,
  SESSION_EXCHANGE_SCOPE,
} from '@seamless-auth/types';
import { constants, sign } from 'crypto';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { Session } from '../models/sessions.js';
import { parseDurationToSeconds } from '../utils/utils.js';
import {
  getOidcAccountClaims,
  PERMISSION_CLAIMS,
  providerTokenClaims,
} from './oidcAccountClaims.js';
import { deriveAcrAmr, resolveCurrentSession, sessionAuthTime } from './oidcAuthContext.js';
import { findActiveOidcClient, getOidcClientResourceScopes } from './oidcClientRegistry.js';
import { hasOidcGrantForSession, recordSessionExchangeToken } from './oidcPayloadStore.js';
import { getActiveOidcSigningKey, OidcProviderKeysError } from './oidcProviderKeys.js';

type JsonObject = Record<string, unknown>;

/**
 * `claims_mismatch`: the account claims in the signing input are not what the API computes for
 * the session and client now. A role or membership can change between the edge's account read
 * and its sign, so the edge reads the account again and retries once. Not yet in the shared
 * refusal codes.
 */
export const CLAIMS_MISMATCH = 'claims_mismatch';
export type SignRefusalCode = OidcSignRefusalCode | typeof CLAIMS_MISMATCH;

export type OidcSignOutcome =
  | { ok: true; kid: string; signature: string }
  | { ok: false; code: SignRefusalCode; userId?: string };

// Anything else in the header (jku, x5u, jwk, crit) would let a verifier be pointed at a
// key we do not control, so it is refused rather than signed.
const ALLOWED_HEADER_MEMBERS = new Set(['alg', 'kid', 'typ']);

// Longer than any provider token lifetime the admin routes will allow, so a signing input
// asking for more is not one the library produced.
const MAX_TOKEN_LIFETIME_SECONDS = 60 * 60 * 24;

const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

// ADR 0003, X2. The edge sets 60 seconds, and this is the most the API will sign.
const MAX_SESSION_EXCHANGE_TOKEN_SECONDS = 120;
// A token the user just signed in for. A refresh is not a sign-in, and the record has to
// say which grant to treat the child as.
const SESSION_EXCHANGE_GRANTS = new Set(['authorization_code', DEVICE_CODE_GRANT]);

const PROTOCOL_CLAIMS = [
  'iss',
  'sub',
  'aud',
  'exp',
  'iat',
  'nbf',
  'jti',
  'auth_time',
  'acr',
  'amr',
  'sid',
];

// What the library puts in each kind of token. Anything else is refused, so the edge cannot
// get a signature over a claim the API never checked.
const ALLOWED_CLAIMS: Record<OidcSignRequest['kind'], ReadonlySet<string>> = {
  id_token: new Set([...PROTOCOL_CLAIMS, 'azp', 'nonce', 'at_hash', 'c_hash', 's_hash']),
  access_token: new Set([...PROTOCOL_CLAIMS, 'client_id', 'scope', 'cnf']),
  client_credentials: new Set([
    'iss',
    'sub',
    'aud',
    'exp',
    'iat',
    'nbf',
    'jti',
    'client_id',
    'scope',
    'cnf',
  ]),
};

// Released by scope, so they may be present, but only with the values the API computes for the
// account and client. Custom claims (ADR 0005 E6) are any other name a custom claim may have.
const ACCOUNT_CLAIMS = new Set<string>([
  'email',
  'email_verified',
  'phone_number',
  'phone_number_verified',
  'roles',
  'org_id',
  ...PERMISSION_CLAIMS,
]);

function isAccountClaimName(claim: string) {
  return (
    ACCOUNT_CLAIMS.has(claim) ||
    (CUSTOM_CLAIM_NAME_PATTERN.test(claim) && !isReservedClaimName(claim))
  );
}

/** JSON equality that ignores object key order, which a JSONB round trip does not keep. */
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical((value as JsonObject)[key])]),
    );
  }
  return value;
}

function sameJson(a: unknown, b: unknown) {
  return JSON.stringify(canonical(a ?? null)) === JSON.stringify(canonical(b ?? null));
}

function isSessionExchangeToken(request: OidcSignRequest, claims: JsonObject) {
  return request.kind === 'access_token' && scopesOf(claims).includes(SESSION_EXCHANGE_SCOPE);
}

function refuse(code: SignRefusalCode, userId?: string): OidcSignOutcome {
  return { ok: false, code, ...(userId ? { userId } : {}) };
}

function decodeSegment(segment: string): JsonObject | null {
  try {
    const value: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as JsonObject)
      : null;
  } catch {
    return null;
  }
}

function sameSet(a: readonly unknown[], b: readonly unknown[]) {
  return (
    a.length === b.length && new Set(a).size === new Set(b).size && a.every((v) => b.includes(v))
  );
}

function trimTrailingSlashes(value: string) {
  let end = value.length;
  while (end > 0 && value[end - 1] === '/') end--;
  return value.slice(0, end);
}

function scopesOf(claims: JsonObject) {
  return typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : [];
}

async function checkResourceAudience(clientId: string, claims: JsonObject, issuer: string) {
  if (typeof claims.aud !== 'string') return 'audience_mismatch' as const;

  // A resource is never the API or the provider itself (ADR 0001, D5), whatever is stored.
  const aud = trimTrailingSlashes(claims.aud);
  const firstParty = process.env.ISSUER;
  if (
    aud === trimTrailingSlashes(issuer) ||
    (firstParty && aud === trimTrailingSlashes(firstParty))
  ) {
    return 'audience_mismatch' as const;
  }

  const allowed = (await getOidcClientResourceScopes(clientId)).get(claims.aud);
  if (!allowed) return 'audience_mismatch' as const;

  return scopesOf(claims).every((scope) => allowed.has(scope))
    ? null
    : ('grant_not_allowed' as const);
}

/**
 * Checks a signing input the edge's `oidc-provider` produced and signs it only if the API
 * would have issued that token itself (ADR 0001, D4). The edge can ask for a token for a
 * user who is signing in now, with the assurance they reached, and nothing else.
 */
export async function signForOidcEdge(request: OidcSignRequest): Promise<OidcSignOutcome> {
  const [encodedHeader, encodedClaims] = request.signingInput.split('.');
  const header = decodeSegment(encodedHeader);
  const claims = decodeSegment(encodedClaims);

  if (
    !header ||
    !claims ||
    header.alg !== 'RS256' ||
    header.kid !== request.kid ||
    Object.keys(header).some((member) => !ALLOWED_HEADER_MEMBERS.has(member))
  ) {
    return refuse('malformed_signing_input');
  }

  const now = Math.floor(Date.now() / 1000);
  if (
    typeof claims.exp !== 'number' ||
    claims.exp <= now ||
    claims.exp - now > MAX_TOKEN_LIFETIME_SECONDS
  ) {
    return refuse('malformed_signing_input');
  }

  const isAccessToken = request.kind !== 'id_token';
  const typOk = isAccessToken
    ? header.typ === 'at+jwt'
    : header.typ === undefined || header.typ === 'JWT';
  if (!typOk) {
    return refuse('malformed_signing_input');
  }

  const allowed = ALLOWED_CLAIMS[request.kind];
  const allowsIdentity = request.kind !== 'client_credentials';
  if (
    Object.keys(claims).some(
      (claim) => !allowed.has(claim) && !(allowsIdentity && isAccountClaimName(claim)),
    )
  ) {
    return refuse('malformed_signing_input');
  }

  let key;
  try {
    key = getActiveOidcSigningKey(request.kid);
  } catch (error) {
    if (error instanceof OidcProviderKeysError) return refuse('unknown_key');
    throw error;
  }
  if (!key) return refuse('unknown_key');

  const { oidc_issuer } = await getSystemConfig();
  if (!oidc_issuer || claims.iss !== oidc_issuer) return refuse('issuer_mismatch');

  const client = await findActiveOidcClient(request.clientId);
  if (!client) return refuse('client_inactive');

  if (request.kind === 'client_credentials') {
    if (claims.sub !== client.id || claims.client_id !== client.id) {
      return refuse('subject_mismatch');
    }
    if (!client.grantTypes.includes('client_credentials')) return refuse('grant_not_allowed');
    if (scopesOf(claims).includes(SESSION_EXCHANGE_SCOPE)) return refuse('grant_not_allowed');

    const audience = await checkResourceAudience(client.id, claims, oidc_issuer);
    if (audience) return refuse(audience);
  } else {
    const refusal = await checkUserToken(request, claims, client, oidc_issuer);
    if (refusal) return refusal;
  }

  const signature = sign('sha256', Buffer.from(request.signingInput), {
    key,
    padding: constants.RSA_PKCS1_PADDING,
  }).toString('base64url');

  if (isSessionExchangeToken(request, claims)) {
    const recorded = await recordSessionExchangeToken(
      claims.jti as string,
      request.sessionId as string,
      {
        clientId: client.id,
        accountId: claims.sub as string,
        grantType: request.grantType as string,
      },
      new Date((claims.exp as number) * 1000),
    );
    if (!recorded) return refuse('malformed_signing_input');
  }

  if (request.kind !== 'client_credentials') {
    await recordProviderActivity(request.sessionId as string);
  }

  return { ok: true, kid: request.kid, signature };
}

/**
 * An app refreshing its tokens is the user still using the session, so each provider token
 * signed for it, and each refresh of a session exchanged from it (ADR 0003, X4), moves the idle
 * expiry forward, never past the absolute lifetime.
 */
export async function recordProviderActivity(sessionId: string) {
  const session = await resolveCurrentSession(sessionId);
  if (!session) return;

  const { session_idle_ttl } = await getSystemConfig();
  const now = new Date();
  const idle = now.getTime() + parseDurationToSeconds(session_idle_ttl || '8h') * 1000;

  await Session.update(
    {
      lastUsedAt: now,
      idleExpiresAt: new Date(Math.min(idle, new Date(session.expiresAt).getTime())),
    },
    { where: { id: session.id } },
  );
}

async function checkUserToken(
  request: OidcSignRequest,
  claims: JsonObject,
  client: { id: string; grantTypes: string[]; firstParty: boolean; deviceFlowEnabled: boolean },
  issuer: string,
): Promise<OidcSignOutcome | null> {
  const device = request.grantType === DEVICE_CODE_GRANT;
  if (
    !request.grantType ||
    !client.grantTypes.includes(request.grantType) ||
    (device && !(client.firstParty && client.deviceFlowEnabled))
  ) {
    return refuse('grant_not_allowed');
  }

  const session = request.sessionId ? await resolveCurrentSession(request.sessionId) : null;
  if (!session) return refuse('session_revoked');
  const sessionId = request.sessionId as string;

  if (claims.sub !== session.userId) return refuse('subject_mismatch', session.userId);

  // A recovery session cannot finish a provider sign-in until a new factor is enrolled.
  if (session.recovery) return refuse('auth_context_mismatch', session.userId);

  // The session must be one a provider sign-in produced for this client, not any live
  // session the edge happens to know the id of.
  if (!(await hasOidcGrantForSession(sessionId, client.id))) {
    return refuse('grant_not_allowed', session.userId);
  }

  const { acr, amr } = deriveAcrAmr(session.authMethods ?? []);
  const authTime = sessionAuthTime(session);

  // ADR 0001, D10. The passkey proves who approved the device, not who holds its tokens, so
  // a device-flow token never states the assurance the approving session earned.
  if (
    device &&
    (claims.acr !== undefined || claims.amr !== undefined || claims.auth_time !== undefined)
  ) {
    return refuse('auth_context_mismatch', session.userId);
  }

  // Omitting a claim only understates assurance. Stating one the session did not earn is
  // what the edge must never be able to do.
  if (
    (claims.acr !== undefined && (acr === null || claims.acr !== acr)) ||
    (claims.amr !== undefined && (!Array.isArray(claims.amr) || !sameSet(claims.amr, amr))) ||
    (claims.auth_time !== undefined && claims.auth_time !== authTime)
  ) {
    return refuse('auth_context_mismatch', session.userId);
  }

  const released = Object.keys(claims).filter((claim) => !ALLOWED_CLAIMS[request.kind].has(claim));
  if (released.length > 0) {
    const refusal = await checkAccountClaims(session, client.id, claims, released);
    if (refusal) return refusal;
  }

  if (request.kind === 'id_token') {
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (audience.length !== 1 || audience[0] !== client.id) {
      return refuse('audience_mismatch', session.userId);
    }
    return null;
  }

  if (claims.client_id !== client.id) return refuse('audience_mismatch', session.userId);

  const audience = await checkResourceAudience(client.id, claims, issuer);
  if (audience) return refuse(audience, session.userId);

  return isSessionExchangeToken(request, claims)
    ? checkSessionExchangeToken(request, claims, issuer, session.userId)
    : null;
}

/**
 * The edge releases account claims by scope, but every value is the API's: it computes them
 * again here for this session and client, the same way `/oidc/accounts/:id` did, and signs
 * only what matches. A custom claim name it did not compute is one it never checked. The
 * permission claims and the custom claims are each carried whole or not at all (ADR 0005 E6),
 * since a partial list looks complete. Each is `claims_mismatch`: a change since the edge's
 * read looks the same as a forgery, so the edge reads the account again and retries once.
 */
async function checkAccountClaims(
  session: NonNullable<Awaited<ReturnType<typeof resolveCurrentSession>>>,
  clientId: string,
  claims: JsonObject,
  released: string[],
): Promise<OidcSignOutcome | null> {
  const account = await getOidcAccountClaims(session, clientId);
  if (!account) return refuse('subject_mismatch', session.userId);

  const expected = providerTokenClaims(account);
  if (
    released.some(
      (claim) =>
        (!ACCOUNT_CLAIMS.has(claim) && !(claim in expected)) ||
        !sameJson(claims[claim], expected[claim]),
    )
  ) {
    return refuse(CLAIMS_MISMATCH, session.userId);
  }

  const sets = [
    PERMISSION_CLAIMS.filter((claim) => claim in expected),
    Object.keys(account.customClaims),
  ];
  for (const set of sets) {
    const carried = set.filter((claim) => claim in claims).length;
    if (carried > 0 && carried < set.length) return refuse(CLAIMS_MISMATCH, session.userId);
  }

  return null;
}

/** ADR 0003, X2: a token useful nowhere else, that lives briefly and can be told apart. */
function checkSessionExchangeToken(
  request: OidcSignRequest,
  claims: JsonObject,
  issuer: string,
  userId: string,
): OidcSignOutcome | null {
  if (claims.aud !== seamlessBuiltInResource(issuer)) return refuse('audience_mismatch', userId);
  if (claims.scope !== SESSION_EXCHANGE_SCOPE) return refuse('grant_not_allowed', userId);
  if (!SESSION_EXCHANGE_GRANTS.has(request.grantType as string)) {
    return refuse('grant_not_allowed', userId);
  }

  const now = Math.floor(Date.now() / 1000);
  if (
    typeof claims.jti !== 'string' ||
    !claims.jti ||
    typeof claims.iat !== 'number' ||
    (claims.exp as number) - claims.iat > MAX_SESSION_EXCHANGE_TOKEN_SECONDS ||
    (claims.exp as number) - now > MAX_SESSION_EXCHANGE_TOKEN_SECONDS
  ) {
    return refuse('malformed_signing_input', userId);
  }

  return null;
}
