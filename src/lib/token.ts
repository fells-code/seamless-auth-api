/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { hashSync } from 'bcrypt-ts';
import { randomBytes } from 'crypto';
import { importPKCS8, SignJWT } from 'jose';

import { getSystemConfig } from '../config/getSystemConfig';
import getLogger from '../utils/logger';
import { getSigningKey } from '../utils/signingKeyStore';

const logger = getLogger('tokens');

const ISSUER = process.env.ISSUER!;

export async function signAccessToken(sessionId: string, userId: string, roles?: string[]) {
  const { kid, privateKeyPem } = await getSigningKey();

  const privateKey = await importPKCS8(privateKeyPem, 'RS256');
  const { access_token_ttl } = await getSystemConfig();

  const jwt = await new SignJWT({
    sid: sessionId,
    sub: userId,
    iss: process.env.ISSUER,
    typ: 'access',
    roles,
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setIssuer(ISSUER)
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
