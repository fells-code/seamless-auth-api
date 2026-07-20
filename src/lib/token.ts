/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { hashSync } from 'bcrypt-ts';
import { createHmac, randomBytes } from 'crypto';
import { importPKCS8, SignJWT } from 'jose';

import { getSystemConfig } from '../config/getSystemConfig.js';
import getLogger from '../utils/logger.js';
import { getSigningKey } from '../utils/signingKeyStore.js';

const logger = getLogger('tokens');

// User tokens are signed with `aud` equal to ISSUER. The Seamless adapter verifies
// signed auth responses with `aud === audience`, and the deployment contract requires
// the adopter's `audience` to equal its `authServerUrl`, which is byte-identical to
// this ISSUER. Omitting `aud` makes jose reject every token the adapter checks.
const ISSUER = process.env.ISSUER!;
let warnedAboutDevLookupSecret = false;

function getRefreshTokenLookupSecret() {
  const explicitSecret = process.env.REFRESH_TOKEN_LOOKUP_SECRET?.trim();
  if (explicitSecret) {
    return explicitSecret;
  }

  const apiServiceSecret = process.env.API_SERVICE_TOKEN?.trim();
  if (apiServiceSecret) {
    return apiServiceSecret;
  }

  if (process.env.NODE_ENV !== 'production') {
    if (!warnedAboutDevLookupSecret) {
      logger.warn(
        'REFRESH_TOKEN_LOOKUP_SECRET is not set. Falling back to a development-only secret for refresh token lookup fingerprints.',
      );
      warnedAboutDevLookupSecret = true;
    }

    return `dev-refresh-lookup:${process.env.APP_ID ?? 'local'}:${ISSUER}`;
  }

  throw new Error(
    'REFRESH_TOKEN_LOOKUP_SECRET (or API_SERVICE_TOKEN) must be set to derive refresh token lookup fingerprints in production.',
  );
}

export async function signAccessToken(
  sessionId: string,
  userId: string,
  roles?: string[],
  organizationId?: string | null,
) {
  const { kid, privateKeyPem } = await getSigningKey();

  const privateKey = await importPKCS8(privateKeyPem, 'RS256');
  const { access_token_ttl } = await getSystemConfig();

  const jwt = await new SignJWT({
    sid: sessionId,
    sub: userId,
    iss: process.env.ISSUER,
    typ: 'access',
    roles,
    ...(organizationId ? { org_id: organizationId } : {}),
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(ISSUER)
    .setExpirationTime(access_token_ttl)
    .sign(privateKey);

  return jwt;
}

export async function signRefreshToken(sessionId: string, userId: string) {
  const { kid, privateKeyPem } = await getSigningKey();

  const privateKey = await importPKCS8(privateKeyPem, 'RS256');
  const { refresh_token_ttl } = await getSystemConfig();

  const jwt = await new SignJWT({
    sid: sessionId,
    sub: userId,
    iss: process.env.ISSUER,
    typ: 'refresh',
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(ISSUER)
    .setExpirationTime(refresh_token_ttl)
    .sign(privateKey);

  return jwt;
}

export async function signEphemeralToken(userId: string) {
  try {
    const { kid, privateKeyPem } = await getSigningKey();

    const privateKey = await importPKCS8(privateKeyPem, 'RS256');

    const jwt = await new SignJWT({
      sub: userId,
      iss: process.env.ISSUER,
      typ: 'ephemeral',
    })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience(ISSUER)
      .setExpirationTime('5m')
      .sign(privateKey);

    return jwt;
  } catch (error) {
    logger.error(`Failed to create JWT token. Ephemeral. Reason: ${error}.`);
    throw new Error('Failed to sign Ephemeral Token');
  }
}

export function generateRefreshToken() {
  return randomBytes(32).toString('base64url');
}

export async function hashRefreshToken(token: string) {
  const saltRounds = 12;
  return hashSync(token, saltRounds);
}

export function createRefreshTokenLookup(token: string) {
  return createHmac('sha256', getRefreshTokenLookupSecret()).update(token).digest('hex');
}
