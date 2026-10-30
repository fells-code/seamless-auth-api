/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { OidcSignRefusalCode, OidcSignRequest } from '@seamless-auth/types';
import { constants, sign } from 'crypto';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { Session } from '../models/sessions.js';
import { parseDurationToSeconds } from '../utils/utils.js';
import { deriveAcrAmr, resolveCurrentSession } from './oidcAuthContext.js';
import {
  findActiveOidcClient,
  getOidcAccountClaims,
  getOidcClientResourceScopes,
} from './oidcClientRegistry.js';
import { hasOidcGrantForSession } from './oidcPayloadStore.js';
import { getActiveOidcSigningKey, OidcProviderKeysError } from './oidcProviderKeys.js';

type JsonObject = Record<string, unknown>;

export type OidcSignOutcome =
  | { ok: true; kid: string; signature: string }
  | { ok: false; code: OidcSignRefusalCode; userId?: string };

// Anything else in the header (jku, x5u, jwk, crit) would let a verifier be pointed at a
// key we do not control, so it is refused rather than signed.
const ALLOWED_HEADER_MEMBERS = new Set(['alg', 'kid', 'typ']);

// Longer than any provider token lifetime the admin routes will allow, so a signing input
// asking for more is not one the library produced.
const MAX_TOKEN_LIFETIME_SECONDS = 60 * 60 * 24;

const USER_CODE_GRANTS = ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'];

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

// Released by scope, so they may be present, but only with the account's own values.
const IDENTITY_CLAIMS = [
  'email',
  'email_verified',
  'phone_number',
  'phone_number_verified',
  'roles',
  'org_id',
] as const;

function refuse(code: OidcSignRefusalCode, userId?: string): OidcSignOutcome {
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

function scopesOf(claims: JsonObject) {
  return typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : [];
}

async function checkResourceAudience(clientId: string, claims: JsonObject, issuer: string) {
  if (typeof claims.aud !== 'string') return 'audience_mismatch' as const;

  // A resource is never the API or the provider itself (ADR 0001, D5), whatever is stored.
  const aud = claims.aud.replace(/\/+$/, '');
  if (aud === issuer.replace(/\/+$/, '') || aud === process.env.ISSUER?.replace(/\/+$/, '')) {
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
      (claim) =>
        !allowed.has(claim) &&
        !(allowsIdentity && (IDENTITY_CLAIMS as readonly string[]).includes(claim)),
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

  if (request.kind !== 'client_credentials') {
    await recordProviderActivity(request.sessionId as string);
  }

  return { ok: true, kid: request.kid, signature };
}

/**
 * An app refreshing its tokens is the user still using the session, so each provider token
 * signed for it moves the idle expiry forward, never past the absolute lifetime.
 */
async function recordProviderActivity(sessionId: string) {
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
  client: { id: string; grantTypes: string[] },
  issuer: string,
): Promise<OidcSignOutcome | null> {
  if (!client.grantTypes.some((grant) => USER_CODE_GRANTS.includes(grant))) {
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
  // Sessions from before the auth context columns fall back to the start of the chain, so
  // a refresh cannot make the sign-in look more recent than it was.
  const authTime = Math.floor(
    new Date(session.authTime ?? session.chainStartedAt ?? session.createdAt).getTime() / 1000,
  );

  // Omitting a claim only understates assurance. Stating one the session did not earn is
  // what the edge must never be able to do.
  if (
    (claims.acr !== undefined && (acr === null || claims.acr !== acr)) ||
    (claims.amr !== undefined && (!Array.isArray(claims.amr) || !sameSet(claims.amr, amr))) ||
    (claims.auth_time !== undefined && claims.auth_time !== authTime)
  ) {
    return refuse('auth_context_mismatch', session.userId);
  }

  if (IDENTITY_CLAIMS.some((claim) => claim in claims)) {
    const account = await getOidcAccountClaims(session.userId);
    const mismatch = IDENTITY_CLAIMS.some(
      (claim) =>
        claim in claims &&
        JSON.stringify(claims[claim]) !== JSON.stringify(account?.[claim] ?? null),
    );
    if (!account || mismatch) return refuse('subject_mismatch', session.userId);
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
  return audience ? refuse(audience, session.userId) : null;
}
