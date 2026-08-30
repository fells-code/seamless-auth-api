/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

import getLogger from '../utils/logger.js';
import { getSecret } from './secretsStore.js';

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

function readDevPrivateKey() {
  try {
    return fs.readFileSync(devPrivateKeyPath, 'utf8');
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function ensureDevKeys() {
  fs.mkdirSync(devKeyDir, { recursive: true });

  const existing = readDevPrivateKey();
  if (existing) {
    return existing;
  }

  // Generate a local RSA keypair in dev
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  try {
    // Exclusive create: two dev processes starting together would otherwise both
    // generate and both write, leaving one of them signing with a key that is not
    // the one on disk and not the one JWKS publishes. Losing the race means
    // adopting the winner's key, not overwriting it.
    fs.writeFileSync(devPrivateKeyPath, privateKey, { encoding: 'utf8', flag: 'wx' });
  } catch (error) {
    if ((error as { code?: string }).code === 'EEXIST') {
      return fs.readFileSync(devPrivateKeyPath, 'utf8');
    }
    throw error;
  }

  fs.writeFileSync(path.join(devKeyDir, 'public.pem'), publicKey, 'utf8');

  logger.info('Generated dev RSA keypair at ./keys/dev/');
  return privateKey;
}

async function loadProdSigningKey(): Promise<SigningKeyCache> {
  const now = Date.now();

  logger.info('Refreshing signing key from env');

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
