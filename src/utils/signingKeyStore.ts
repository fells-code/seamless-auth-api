/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
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
const DEFAULT_DEV_KEYS_DIR = './keys/dev';

export function getDevKeyDir() {
  return path.resolve(process.env.SEAMLESS_DEV_KEYS_DIR || DEFAULT_DEV_KEYS_DIR);
}

function devPrivateKeyPath() {
  return path.join(getDevKeyDir(), 'private.pem');
}

export type DevSigningKey = {
  kid: string;
  privateKeyPem: string;
  publicKeyPem: string;
};

let devKeyCache: DevSigningKey | null = null;

/**
 * RFC 7638 thumbprint of the public half, so a regenerated key gets a new kid. Adapters
 * only refetch JWKS on an unknown kid, so a constant kid left them holding the old key.
 */
export function deriveDevKid(publicKeyPem: string) {
  const { e, n } = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
  const thumbprint = crypto
    .createHash('sha256')
    .update(JSON.stringify({ e, kty: 'RSA', n }))
    .digest('base64url');
  return `dev-${thumbprint.slice(0, 16)}`;
}

// The public half is always derived from private.pem, so a key directory where only the
// private key survived still publishes and verifies.
function toDevSigningKey(privateKeyPem: string): DevSigningKey {
  if (devKeyCache?.privateKeyPem === privateKeyPem) {
    return devKeyCache;
  }

  const publicKeyPem = crypto
    .createPublicKey(privateKeyPem)
    .export({ type: 'spki', format: 'pem' })
    .toString();

  devKeyCache = { kid: deriveDevKid(publicKeyPem), privateKeyPem, publicKeyPem };
  return devKeyCache;
}

function readDevPrivateKey() {
  try {
    return fs.readFileSync(devPrivateKeyPath(), 'utf8');
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function ensureDevKeys() {
  const keyDir = getDevKeyDir();
  const privateKeyPath = devPrivateKeyPath();
  fs.mkdirSync(keyDir, { recursive: true });

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
    fs.writeFileSync(privateKeyPath, privateKey, { encoding: 'utf8', flag: 'wx' });
  } catch (error) {
    if ((error as { code?: string }).code === 'EEXIST') {
      return fs.readFileSync(privateKeyPath, 'utf8');
    }
    throw error;
  }

  fs.writeFileSync(path.join(keyDir, 'public.pem'), publicKey, 'utf8');

  logger.info(`Generated dev RSA keypair at ${keyDir}`);
  return privateKey;
}

/**
 * Creates the dev key pair if it does not exist yet. Called at startup, before the server
 * listens, so JWKS publishes a key from the first request instead of after the first
 * sign-in. A no-op outside development.
 */
export function initDevSigningKey(): DevSigningKey | null {
  if (!isDev) {
    return null;
  }

  const key = toDevSigningKey(ensureDevKeys());
  logger.info(`Dev signing key ready (kid=${key.kid})`);
  return key;
}

/** The current dev key, or null when none has been generated. Never creates one. */
export function getDevSigningKey(): DevSigningKey | null {
  const privateKeyPem = readDevPrivateKey();
  return privateKeyPem ? toDevSigningKey(privateKeyPem) : null;
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
    const devKey = getDevSigningKey();
    if (!devKey) {
      logger.warn(`Dev signing key missing for kid=${kid}`);
      return null;
    }
    if (devKey.kid !== kid) {
      logger.warn(`Unknown dev kid=${kid}, current dev kid is ${devKey.kid}`);
      return null;
    }
    return devKey.publicKeyPem;
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
    const { kid, privateKeyPem } = toDevSigningKey(ensureDevKeys());

    cache = {
      kid,
      privateKeyPem,
      loadedAt: now,
    };

    return { kid, privateKeyPem };
  }

  if (!cache) {
    return loadProdSigningKey();
  }

  if (now - cache.loadedAt >= ACTIVE_KID_TTL_MS) {
    loadProdSigningKey().catch((err) => logger.error('Failed async refresh of signing key', err));
  }

  return { kid: cache.kid, privateKeyPem: cache.privateKeyPem };
}
