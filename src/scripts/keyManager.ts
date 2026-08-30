/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import crypto from 'crypto';
import { access, mkdir, writeFile } from 'fs/promises';
import path from 'path';

import getLogger from '../utils/logger.js';

const logger = getLogger('jwks-bootstrap');

const isProduction = process.env.NODE_ENV === 'production';

const localKeyDir = path.resolve('./keys');
const localPrivate = path.join(localKeyDir, 'private.pem');
const localPublic = path.join(localKeyDir, 'public.pem');

// A fast path only: the exclusive write below is what actually settles a race, so a
// stale answer here costs a wasted keypair, never a clobbered one.
async function pathExists(target: string) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

// Create local keys if needed
async function ensureLocalDevKeys() {
  await mkdir(localKeyDir, { recursive: true });

  if (await pathExists(localPrivate)) {
    logger.info('Dev keys already exist.');
    return;
  }

  logger.info('Generating new dev RSA keypair...');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  try {
    // Exclusive create rather than exists-then-write: the pair must come from one
    // generation, and a concurrent run must not replace a private key whose public
    // half has already been published.
    await writeFile(localPrivate, privateKey, { flag: 'wx' });
  } catch (error) {
    if ((error as { code?: string }).code === 'EEXIST') {
      logger.info('Dev keys already exist.');
      return;
    }
    throw error;
  }

  await writeFile(localPublic, publicKey);
  logger.info('Dev keypair created in ./keys/');
}

export async function ensureKeys() {
  if (!isProduction) {
    // local development mode
    logger.info('Running in dev mode → using local keys.');
    return ensureLocalDevKeys();
  }

  // PRODUCTION MODE
  // Implement a first time JWKS rotation. See Seamless Auth docs for guides
}
