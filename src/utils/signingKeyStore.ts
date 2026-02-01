/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

import getLogger from '../utils/logger';
import { getSecret } from './secretsStore';

const logger = getLogger('signing-key-store');

const jwksPrefix = `SEAMLESS_JWKS`;

const isDev = process.env.NODE_ENV !== 'production';

type SigningKeyCache = {
  kid: string;
  privateKeyPem: string;
  loadedAt: number;
};

type PublicKeyCacheItem = {
  pem: string;
  loadedAt: number;
};

const PUBLIC_KEY_TTL_MS = 1000 * 60 * 5;
let publicKeyCache: Record<string, PublicKeyCacheItem> = {};

let cache: SigningKeyCache | null = null;
const ACTIVE_KID_TTL_MS = 1000 * 60 * 5;
const devKeyDir = path.resolve('./keys/dev');
const devPrivateKeyPath = path.join(devKeyDir, 'private.pem');
const devKid = 'dev-main';

function ensureDevKeys() {
  if (!fs.existsSync(devKeyDir)) {
    fs.mkdirSync(devKeyDir, { recursive: true });
  }

  if (fs.existsSync(devPrivateKeyPath)) {
    return fs.readFileSync(devPrivateKeyPath, 'utf8');
  }

  // Generate a local RSA keypair in dev
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(devPrivateKeyPath, privateKey, 'utf8');
  fs.writeFileSync(path.join(devKeyDir, 'public.pem'), publicKey, 'utf8');

  logger.info('Generated dev RSA keypair at ./keys/dev/');
  return privateKey;
}

async function loadProdSigningKey(): Promise<SigningKeyCache> {
  const now = Date.now();

  logger.info('Refreshing signing key from Secrets Manager');

  const activeKid = await getSecret(`${jwksPrefix}_ACTIVE_KID`);
  const privateKeySecretName = `${jwksPrefix}_KEY_${activeKid}_PRIVATE`;
  const privateKeyPem = await getSecret(privateKeySecretName);

  const cacheValue = {
    kid: activeKid,
    privateKeyPem,
    loadedAt: now,
  };

  cache = cacheValue;
  return cacheValue;
}

async function loadAllPublicKeys(): Promise<void> {
  const secretName = `${jwksPrefix}_PUBLIC_KEYS`;
  const raw = await getSecret(secretName);

  if (!raw) {
    logger.error(`No public_keys secret found at: ${secretName}`);
    return;
  }

  try {
    const parsed = JSON.parse(raw) as {
      keys: { kid: string; pem: string; createdAt: string }[];
    };

    for (const { kid, pem } of parsed.keys) {
      publicKeyCache[kid] = {
        pem,
        loadedAt: Date.now(),
      };
    }

    logger.info(`Loaded ${parsed.keys.length} public signing keys`);
  } catch (err) {
    logger.error('Failed to parse public_keys secret:', err);
  }
}

export async function getPublicKeyByKid(kid: string): Promise<string | null> {
  const now = Date.now();

  // DEV MODE
  if (isDev) {
    const devKeyPath = path.join(devKeyDir, 'public.pem');
    if (!fs.existsSync(devKeyPath)) {
      logger.warn(`Dev public.pem missing for kid=${kid}`);
      return null;
    }
    return fs.readFileSync(devKeyPath, 'utf8');
  }

  // PROD
  const cached = publicKeyCache[kid];

  if (cached && now - cached.loadedAt < PUBLIC_KEY_TTL_MS) {
    return cached.pem;
  }

  // TTL expired or not in cache → reload entire secret
  await loadAllPublicKeys();

  return publicKeyCache[kid]?.pem ?? null;
}

export async function getSigningKey() {
  const now = Date.now();

  if (isDev) {
    const privateKeyPem = ensureDevKeys();

    cache = {
      kid: devKid,
      privateKeyPem,
      loadedAt: now,
    };

    return { kid: devKid, privateKeyPem };
  }

  if (!cache) {
    return loadProdSigningKey();
  }

  if (now - cache.loadedAt >= ACTIVE_KID_TTL_MS) {
    loadProdSigningKey().catch((err) => logger.error('Failed async refresh of signing key', err));
  }

  return { kid: cache.kid, privateKeyPem: cache.privateKeyPem };
}
