/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const DEFAULT_TOTP_DIGITS = 6;
export const DEFAULT_TOTP_PERIOD_SECONDS = 30;
export const DEFAULT_TOTP_ALGORITHM = 'SHA1';
export const DEFAULT_TOTP_WINDOW = 1;

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

export function base32Encode(buffer: Buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

export function base32Decode(secret: string) {
  const normalized = secret.toUpperCase().replace(/[\s=-]/g, '');
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);

    if (index === -1) {
      throw new Error('Invalid base32 secret');
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

export function generateTotpSecret(byteLength = 20) {
  return base32Encode(randomBuffer(byteLength));
}

function counterBuffer(counter: number) {
  const buffer = Buffer.alloc(8);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;

  buffer.writeUInt32BE(high, 0);
  buffer.writeUInt32BE(low, 4);

  return buffer;
}

export function getTotpCounter(
  timestamp = Date.now(),
  periodSeconds = DEFAULT_TOTP_PERIOD_SECONDS,
) {
  return Math.floor(timestamp / 1000 / periodSeconds);
}

export function generateTotpCode({
  secret,
  counter = getTotpCounter(),
  digits = DEFAULT_TOTP_DIGITS,
}: {
  secret: string;
  counter?: number;
  digits?: number;
}) {
  const key = base32Decode(secret);
  const digest = createHmac('sha1', key).update(counterBuffer(counter)).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  const token = binary % 10 ** digits;

  return token.toString().padStart(digits, '0');
}

function codesMatch(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

export function verifyTotpCode({
  secret,
  code,
  timestamp = Date.now(),
  window = DEFAULT_TOTP_WINDOW,
  digits = DEFAULT_TOTP_DIGITS,
  periodSeconds = DEFAULT_TOTP_PERIOD_SECONDS,
  lastUsedCounter = null,
}: {
  secret: string;
  code: string;
  timestamp?: number;
  window?: number;
  digits?: number;
  periodSeconds?: number;
  lastUsedCounter?: number | null;
}) {
  if (!new RegExp(`^\\d{${digits}}$`).test(code)) {
    return { verified: false, counter: null };
  }

  const currentCounter = getTotpCounter(timestamp, periodSeconds);

  for (let offset = -window; offset <= window; offset += 1) {
    const counter = currentCounter + offset;

    if (counter < 0 || (lastUsedCounter !== null && counter <= lastUsedCounter)) {
      continue;
    }

    const expected = generateTotpCode({ secret, counter, digits });

    if (codesMatch(expected, code)) {
      return { verified: true, counter };
    }
  }

  return { verified: false, counter: null };
}

export function buildTotpUri({
  issuer,
  accountName,
  secret,
  digits = DEFAULT_TOTP_DIGITS,
  periodSeconds = DEFAULT_TOTP_PERIOD_SECONDS,
}: {
  issuer: string;
  accountName: string;
  secret: string;
  digits?: number;
  periodSeconds?: number;
}) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: DEFAULT_TOTP_ALGORITHM,
    digits: String(digits),
    period: String(periodSeconds),
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}
