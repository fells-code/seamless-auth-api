/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import crypto from 'crypto';
import * as fs from 'fs';
import { mkdir, writeFile } from 'fs/promises';
import path from 'path';

import getLogger from '../utils/logger';

const logger = getLogger('jwks-bootstrap');

const isProduction = process.env.NODE_ENV === 'production';

const localKeyDir = path.resolve('./keys');
const localPrivate = path.join(localKeyDir, 'private.pem');
const localPublic = path.join(localKeyDir, 'public.pem');

// Create local keys if needed
async function ensureLocalDevKeys() {
  if (!fs.existsSync(localKeyDir)) {
    await mkdir(localKeyDir, { recursive: true });
  }

  if (fs.existsSync(localPrivate) && fs.existsSync(localPublic)) {
    logger.info('Dev keys already exist.');
    return;
  }

  logger.info('Generating new dev RSA keypair...');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  await writeFile(localPrivate, privateKey);
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
