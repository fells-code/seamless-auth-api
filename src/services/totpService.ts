/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';

import { TotpCredential } from '../models/totpCredentials.js';
import {
  buildTotpUri,
  DEFAULT_TOTP_ALGORITHM,
  DEFAULT_TOTP_DIGITS,
  DEFAULT_TOTP_PERIOD_SECONDS,
  generateTotpSecret,
  verifyTotpCode,
} from '../utils/totp.js';

const TOTP_CIPHER = 'aes-256-gcm';

type TotpCredentialLike = Pick<
  TotpCredential,
  'secretCiphertext' | 'secretIv' | 'secretTag' | 'lastUsedCounter' | 'update' | 'destroy'
>;

function randomBuffer(length: number) {
  const value = randomBytes(length);

  if (Buffer.isBuffer(value)) {
    return value;
  }

  const fallback = Buffer.from(String(value));

  if (fallback.length >= length) {
    return fallback.subarray(0, length);
  }

  return Buffer.concat([fallback, Buffer.alloc(length - fallback.length)]).subarray(0, length);
}

function getTotpEncryptionKey() {
  const explicitSecret =
    process.env.TOTP_SECRET_ENCRYPTION_KEY?.trim() || process.env.API_SERVICE_TOKEN?.trim();

  if (explicitSecret) {
    return createHash('sha256').update(explicitSecret).digest();
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('TOTP_SECRET_ENCRYPTION_KEY or API_SERVICE_TOKEN must be set in production.');
  }

  return createHash('sha256')
    .update(`dev-totp-secret:${process.env.APP_ID ?? 'local'}:${process.env.ISSUER ?? 'local'}`)
    .digest();
}

export function encryptTotpSecret(secret: string) {
  const iv = randomBuffer(12);
  const cipher = createCipheriv(TOTP_CIPHER, getTotpEncryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);

  return {
    secretCiphertext: ciphertext.toString('base64'),
    secretIv: iv.toString('base64'),
    secretTag: cipher.getAuthTag().toString('base64'),
  };
}

export function decryptTotpSecret(credential: TotpCredentialLike) {
  const decipher = createDecipheriv(
    TOTP_CIPHER,
    getTotpEncryptionKey(),
    Buffer.from(credential.secretIv, 'base64'),
  );

  decipher.setAuthTag(Buffer.from(credential.secretTag, 'base64'));

  return Buffer.concat([
    decipher.update(Buffer.from(credential.secretCiphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

function normalizeCounter(counter: number | string | null | undefined) {
  if (counter === null || counter === undefined) {
    return null;
  }

  return Number(counter);
}

export async function getTotpStatus(userId: string) {
  const credential = await TotpCredential.findOne({
    where: { userId, enabled: true },
  });

  return {
    enabled: Boolean(credential),
    verifiedAt: credential?.verifiedAt ?? null,
    lastUsedAt: credential?.lastUsedAt ?? null,
  };
}

export async function startTotpEnrollment({
  userId,
  email,
  issuer,
}: {
  userId: string;
  email: string;
  issuer: string;
}) {
  const secret = generateTotpSecret();
  const encryptedSecret = encryptTotpSecret(secret);

  await TotpCredential.create({
    userId,
    ...encryptedSecret,
    issuer,
    accountName: email,
    enabled: false,
    verifiedAt: null,
    lastUsedAt: null,
    lastUsedCounter: null,
  });

  return {
    secret,
    otpauthUrl: buildTotpUri({
      issuer,
      accountName: email,
      secret,
    }),
    issuer,
    accountName: email,
    algorithm: DEFAULT_TOTP_ALGORITHM,
    digits: DEFAULT_TOTP_DIGITS,
    period: DEFAULT_TOTP_PERIOD_SECONDS,
  };
}

async function findLatestPendingCredential(userId: string) {
  return TotpCredential.findOne({
    where: { userId, enabled: false },
    order: [['createdAt', 'DESC']],
  });
}

async function findEnabledCredential(userId: string) {
  return TotpCredential.findOne({
    where: { userId, enabled: true },
  });
}

async function verifyCredentialCode(credential: TotpCredential, code: string) {
  const secret = decryptTotpSecret(credential);

  return verifyTotpCode({
    secret,
    code,
    lastUsedCounter: normalizeCounter(credential.lastUsedCounter),
  });
}

export async function verifyTotpEnrollment(userId: string, code: string) {
  const credential = await findLatestPendingCredential(userId);

  if (!credential) {
    return { verified: false, reason: 'missing_pending_credential' };
  }

  const verification = await verifyCredentialCode(credential, code);

  if (!verification.verified || verification.counter === null) {
    return { verified: false, reason: 'invalid_code' };
  }

  const now = new Date();
  await TotpCredential.update({ enabled: false }, { where: { userId, enabled: true } });
  await credential.update({
    enabled: true,
    verifiedAt: now,
    lastUsedAt: now,
    lastUsedCounter: verification.counter,
  });

  return { verified: true, credential };
}

export async function verifyEnabledTotp(userId: string, code: string) {
  const credential = await findEnabledCredential(userId);

  if (!credential) {
    return { verified: false, reason: 'missing_enabled_credential' };
  }

  const verification = await verifyCredentialCode(credential, code);

  if (!verification.verified || verification.counter === null) {
    return { verified: false, reason: 'invalid_code' };
  }

  await credential.update({
    lastUsedAt: new Date(),
    lastUsedCounter: verification.counter,
  });

  return { verified: true, credential };
}

export async function disableTotp(userId: string, code: string) {
  const credential = await findEnabledCredential(userId);

  if (!credential) {
    return { disabled: false, reason: 'missing_enabled_credential' };
  }

  const verification = await verifyCredentialCode(credential, code);

  if (!verification.verified) {
    return { disabled: false, reason: 'invalid_code' };
  }

  await credential.destroy();

  return { disabled: true };
}
