/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { createCipheriv, createDecipheriv, createHash } from 'crypto';
import { Op } from 'sequelize';

import { authSecret } from '../config/authSecrets.js';
import { TotpCredential } from '../models/totpCredentials.js';
import {
  buildTotpUri,
  DEFAULT_TOTP_ALGORITHM,
  DEFAULT_TOTP_DIGITS,
  DEFAULT_TOTP_PERIOD_SECONDS,
  generateTotpSecret,
  randomBuffer,
  verifyTotpCode,
} from '../utils/totp.js';

const TOTP_CIPHER = 'aes-256-gcm';

class TotpClaimLost extends Error {}

type TotpCredentialLike = Pick<
  TotpCredential,
  'secretCiphertext' | 'secretIv' | 'secretTag' | 'lastUsedCounter' | 'update' | 'destroy'
>;

function getTotpEncryptionKey() {
  return createHash('sha256').update(authSecret('TOTP_SECRET_ENCRYPTION_KEY')).digest();
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

  // Only the newest pending secret is ever redeemed, and leaving the older ones behind
  // both grew the table without limit and kept every superseded secret enrollable.
  await TotpCredential.destroy({ where: { userId, enabled: false } });

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
  const counter = verification.counter;
  try {
    await TotpCredential.sequelize!.transaction(async (transaction) => {
      await TotpCredential.update(
        { enabled: false },
        { where: { userId, enabled: true, id: { [Op.ne]: credential.id } }, transaction },
      );

      // A concurrent enrollment with the same code, or a newer one that destroyed this
      // pending row, leaves nothing to enable, and the disable above must not stand alone.
      const [claimed] = await TotpCredential.update(
        { enabled: true, verifiedAt: now, lastUsedAt: now, lastUsedCounter: counter },
        { where: { id: credential.id, enabled: false }, transaction },
      );

      if (claimed === 0) {
        throw new TotpClaimLost();
      }
    });
  } catch (error) {
    if (error instanceof TotpClaimLost) {
      return { verified: false, reason: 'invalid_code' };
    }
    throw error;
  }

  Object.assign(credential, {
    enabled: true,
    verifiedAt: now,
    lastUsedAt: now,
    lastUsedCounter: counter,
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

  // Two requests with the same code both pass verifyTotpCode against the counter they
  // read, so only the update that still finds an older counter accepts the code.
  const now = new Date();
  const [claimed] = await TotpCredential.update(
    { lastUsedAt: now, lastUsedCounter: verification.counter },
    {
      where: {
        id: credential.id,
        enabled: true,
        [Op.or]: [
          { lastUsedCounter: null },
          { lastUsedCounter: { [Op.lt]: verification.counter } },
        ],
      },
    },
  );

  if (claimed === 0) {
    return { verified: false, reason: 'invalid_code' };
  }

  Object.assign(credential, { lastUsedAt: now, lastUsedCounter: verification.counter });

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
