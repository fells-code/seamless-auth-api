/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request, Response } from 'express';
import fs from 'fs';
import { exportJWK, importSPKI, JWK } from 'jose';

import getLogger from '../utils/logger';
import { getSecret } from '../utils/secretsStore';

const logger = getLogger('jwks');

type JwkCache = {
  keys: JWK[];
  loadedAt: number;
};

let jwkCache: JwkCache | null = null;

const CACHE_TTL = 1000 * 60 * 5;

async function loadJwksFromSecrets(): Promise<JWK[]> {
  logger.info('Loading JWKS from Secrets Manager');

  const raw = await getSecret('JWKS_PUBLIC_KEYS');
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

export async function jwksHandler(req: Request, res: Response) {
  if (process.env.NODE_ENV === 'development') {
    const publicPem = fs.readFileSync('./keys/dev/public.pem', 'utf8');
    const publicKey = await importSPKI(publicPem, 'RS256');
    const jwk = await exportJWK(publicKey);

    return res.json({
      keys: [
        {
          ...jwk,
          kty: 'RSA',
          kid: 'dev-main',
          alg: 'RS256',
          use: 'sig',
        },
      ],
    });
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
