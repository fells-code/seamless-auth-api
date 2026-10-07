/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';
import { exportJWK, importSPKI, JWK } from 'jose';

import getLogger from '../utils/logger.js';
import { getSecret } from '../utils/secretsStore.js';
import { getDevSigningKey } from '../utils/signingKeyStore.js';

const logger = getLogger('jwks');

type JwkCache = {
  keys: JWK[];
  loadedAt: number;
};

let jwkCache: JwkCache | null = null;

const CACHE_TTL = 1000 * 60 * 5;

export function __resetJwksCache() {
  jwkCache = null;
}

async function loadJwksFromSecrets(): Promise<JWK[]> {
  logger.info('Loading JWKS from Secrets Manager');

  const raw = await getSecret('SEAMLESS_JWKS_PUBLIC_KEYS');
  const parsed = JSON.parse(raw);

  const jwks: JWK[] = [];

  for (const k of parsed.keys) {
    const publicKey = await importSPKI(k.pem, 'RS256');
    const jwk = await exportJWK(publicKey);

    jwks.push({
      ...jwk,
      alg: 'RS256',
      use: 'sig',
      kty: 'RSA',
      kid: k.kid,
    });
  }

  return jwks;
}

async function getJwks(): Promise<JWK[]> {
  const now = Date.now();

  if (jwkCache && now - jwkCache.loadedAt < CACHE_TTL) {
    return jwkCache.keys;
  }

  const keys = await loadJwksFromSecrets();
  jwkCache = {
    keys,
    loadedAt: now,
  };

  return keys;
}

// An empty set rather than a 500 when there is no dev key yet: a client polling JWKS
// before startup created one should see "no keys", not a broken server.
async function loadDevJwks(): Promise<JWK[]> {
  try {
    const devKey = getDevSigningKey();
    if (!devKey) {
      logger.warn('No dev signing key found, serving an empty JWKS');
      return [];
    }

    const jwk = await exportJWK(await importSPKI(devKey.publicKeyPem, 'RS256'));
    return [{ ...jwk, kty: 'RSA', kid: devKey.kid, alg: 'RS256', use: 'sig' }];
  } catch (err) {
    logger.error('Failed to load dev signing key, serving an empty JWKS', err);
    return [];
  }
}

export async function jwksHandler(req: Request, res: Response) {
  // Matches the gate in signingKeyStore, which is what decides whether the dev key is
  // the one signing. Testing for 'development' meant any other non-production value
  // signed with the dev key while JWKS refused to publish it.
  if (process.env.NODE_ENV !== 'production') {
    return res.json({ keys: await loadDevJwks() });
  }

  try {
    const keys = await getJwks();

    res.setHeader('Cache-Control', 'public, max-age=300');
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys });
  } catch (err) {
    logger.error('Failed JWKS request', err);
    res.status(500).json({ error: 'JWKS unavailable' });
  }
}
