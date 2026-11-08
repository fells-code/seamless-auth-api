/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';

import {
  WEBHOOK_ID_HEADER,
  WEBHOOK_SECRET_PREFIX,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_SIGNATURE_VERSION,
  WEBHOOK_TIMESTAMP_HEADER,
} from '@seamless-auth/types';

import { authSecret } from '../config/authSecrets.js';

/**
 * Standard Webhooks signing (ADR 0005, D1), for webhooks and login hook calls alike. The secret
 * is `whsec_` and base64 of 32 random bytes, and the HMAC key is those decoded bytes.
 */
export function generateCalloutSecret() {
  return `${WEBHOOK_SECRET_PREFIX}${randomBytes(32).toString('base64')}`;
}

function secretKey(secret: string) {
  return Buffer.from(secret.slice(WEBHOOK_SECRET_PREFIX.length), 'base64');
}

export function calloutSignature(id: string, timestamp: number, body: string, secret: string) {
  const signature = createHmac('sha256', secretKey(secret))
    .update(`${id}.${timestamp}.${body}`)
    .digest('base64');

  return `${WEBHOOK_SIGNATURE_VERSION},${signature}`;
}

/**
 * The three Standard Webhooks headers. While a secret rotates, both secrets sign, separated by a
 * space, so a receiver holding either one verifies.
 */
export function signedCalloutHeaders(
  id: string,
  body: string,
  secrets: readonly string[],
  now: Date = new Date(),
): Record<string, string> {
  const timestamp = Math.floor(now.getTime() / 1000);

  return {
    'content-type': 'application/json',
    [WEBHOOK_ID_HEADER]: id,
    [WEBHOOK_TIMESTAMP_HEADER]: String(timestamp),
    [WEBHOOK_SIGNATURE_HEADER]: secrets
      .map((secret) => calloutSignature(id, timestamp, body, secret))
      .join(' '),
  };
}

const CIPHER = 'aes-256-gcm';

export type EncryptedCalloutSecret = {
  ciphertext: string;
  iv: string;
  tag: string;
};

// Signing secrets have to be read back to sign, so they cannot be hashed (ADR 0005, D9).
function encryptionKey() {
  return createHash('sha256').update(authSecret('CALLOUT_SECRET_ENCRYPTION_KEY')).digest();
}

export function encryptCalloutSecret(secret: string): EncryptedCalloutSecret {
  const iv = randomBytes(12);
  const cipher = createCipheriv(CIPHER, encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

export function decryptCalloutSecret({ ciphertext, iv, tag }: EncryptedCalloutSecret) {
  const decipher = createDecipheriv(CIPHER, encryptionKey(), Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}
