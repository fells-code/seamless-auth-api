/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { OidcSignRefusalCode, OidcSignRequest } from '@seamless-auth/types';
import { constants, sign } from 'crypto';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { deriveAcrAmr, resolveCurrentSession } from './oidcAuthContext.js';
import { findActiveOidcClient, getOidcClientResourceScopes } from './oidcClientRegistry.js';
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

async function checkResourceAudience(clientId: string, claims: JsonObject) {
  if (typeof claims.aud !== 'string') return 'audience_mismatch' as const;

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
  if (isAccessToken !== (header.typ === 'at+jwt')) {
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

    const audience = await checkResourceAudience(client.id, claims);
    if (audience) return refuse(audience);
  } else {
    const refusal = await checkUserToken(request, claims, client);
    if (refusal) return refusal;
  }

  const signature = sign('sha256', Buffer.from(request.signingInput), {
    key,
    padding: constants.RSA_PKCS1_PADDING,
  }).toString('base64url');

  return { ok: true, kid: request.kid, signature };
}

async function checkUserToken(
  request: OidcSignRequest,
  claims: JsonObject,
  client: { id: string; grantTypes: string[] },
): Promise<OidcSignOutcome | null> {
  if (!client.grantTypes.some((grant) => USER_CODE_GRANTS.includes(grant))) {
    return refuse('grant_not_allowed');
  }

  const session = request.sessionId ? await resolveCurrentSession(request.sessionId) : null;
  if (!session) return refuse('session_revoked');

  if (claims.sub !== session.userId) return refuse('subject_mismatch', session.userId);

  // A recovery session cannot finish a provider sign-in until a new factor is enrolled.
  if (session.recovery) return refuse('auth_context_mismatch', session.userId);

  const { acr, amr } = deriveAcrAmr(session.authMethods ?? []);
  const authTime = Math.floor(new Date(session.authTime ?? session.createdAt).getTime() / 1000);

  // Omitting a claim only understates assurance. Stating one the session did not earn is
  // what the edge must never be able to do.
  if (
    (claims.acr !== undefined && (acr === null || claims.acr !== acr)) ||
    (claims.amr !== undefined && (!Array.isArray(claims.amr) || !sameSet(claims.amr, amr))) ||
    (claims.auth_time !== undefined && claims.auth_time !== authTime)
  ) {
    return refuse('auth_context_mismatch', session.userId);
  }

  if (request.kind === 'id_token') {
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (audience.length !== 1 || audience[0] !== client.id) {
      return refuse('audience_mismatch', session.userId);
    }
    return null;
  }

  if (claims.client_id !== client.id) return refuse('audience_mismatch', session.userId);

  const audience = await checkResourceAudience(client.id, claims);
  return audience ? refuse(audience, session.userId) : null;
}
