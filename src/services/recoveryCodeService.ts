/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { createHmac, randomInt } from 'crypto';

import { authSecret } from '../config/authSecrets.js';
import { RecoveryCode } from '../models/recoveryCodes.js';

export const RECOVERY_CODE_COUNT = 10;

// RFC 4648 base32: no 0/1/8/9, so a code copied from paper cannot be misread as O/I/B/g.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HALF = 5;

function generateCode() {
  let code = '';
  for (let i = 0; i < HALF * 2; i += 1) {
    code += ALPHABET[randomInt(ALPHABET.length)];
  }
  return `${code.slice(0, HALF)}-${code.slice(HALF)}`;
}

/** What a user typed, in the one form codes are hashed in: upper case, no dash or spaces. */
export function normalizeRecoveryCode(code: string) {
  return code.replace(/[\s-]/g, '').toUpperCase();
}

/**
 * Keyed with the refresh lookup secret, under its own label, rather than plain SHA-256:
 * a code is 50 bits, few enough that an unkeyed hash taken from a database dump could be
 * searched offline. Rotating that secret therefore also voids every recovery code.
 */
function hashRecoveryCode(code: string) {
  return createHmac('sha256', authSecret('REFRESH_TOKEN_LOOKUP_SECRET'))
    .update(`recovery-code:${normalizeRecoveryCode(code)}`)
    .digest('hex');
}

export async function getRecoveryCodeStatus(userId: string) {
  const codes = await RecoveryCode.findAll({
    where: { userId },
    attributes: ['usedAt', 'createdAt'],
  });

  const createdAt = codes.reduce<Date | null>(
    (oldest, code) => (oldest && oldest <= code.createdAt ? oldest : code.createdAt),
    null,
  );

  return {
    remaining: codes.filter((code) => !code.usedAt).length,
    total: codes.length,
    createdAt,
  };
}

/**
 * Replaces the user's set with a new one and returns the codes, which are never stored
 * or shown again.
 */
export async function generateRecoveryCodes(userId: string) {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, generateCode);
  const createdAt = new Date();

  await RecoveryCode.sequelize!.transaction(async (transaction) => {
    await RecoveryCode.destroy({ where: { userId }, transaction });
    await RecoveryCode.bulkCreate(
      codes.map((code) => ({ userId, codeHash: hashRecoveryCode(code), createdAt })),
      { transaction },
    );
  });

  return { codes, createdAt };
}

/**
 * Spends one code if it is the user's and unused. The update is conditional on `usedAt`
 * being null, so two requests with the same code cannot both succeed.
 */
export async function redeemRecoveryCode(userId: string, code: string) {
  const [spent] = await RecoveryCode.update(
    { usedAt: new Date() },
    { where: { userId, codeHash: hashRecoveryCode(code), usedAt: null } },
  );

  return spent === 1;
}
