/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto';

import { authSecret } from '../config/authSecrets.js';

const DEFAULT_WINDOW_SECONDS = 5;
const MAX_WINDOW_SECONDS = 60;

/** How many times a rotated refresh token may be answered again inside the window. */
export const MAX_REFRESH_REPLAYS = 3;

// Not a valid refresh token (`:` is outside base64url), so the key input can never equal
// the input of a stored refresh token lookup.
const KEY_CONTEXT = 'seamless-refresh-replay:v1:';
const FORMAT = 'v1';
const AUTH_TAG_LENGTH = 16;

/**
 * How long after a rotation the rotated token is still answered with the same successor,
 * so two adapter instances refreshing at once do not read as reuse. `0` disables it.
 */
export function refreshReplayWindowMs(env: Record<string, string | undefined> = process.env) {
  const raw = env.REFRESH_REPLAY_WINDOW_SECONDS;
  const seconds = raw === undefined || raw.trim() === '' ? DEFAULT_WINDOW_SECONDS : Number(raw);

  if (!Number.isFinite(seconds) || seconds <= 0) return 0;

  return Math.min(seconds, MAX_WINDOW_SECONDS) * 1000;
}

// Keyed by the rotated token as well as the server secret, so the stored ciphertext is
// useless to anyone who does not already hold the token it answers for.
function replayKey(predecessorToken: string) {
  return createHmac('sha256', authSecret('REFRESH_TOKEN_LOOKUP_SECRET'))
    .update(KEY_CONTEXT)
    .update(predecessorToken)
    .digest();
}

function associatedData(predecessorId: string, successorId: string) {
  return Buffer.from(`${predecessorId}:${successorId}`);
}

export interface ReplayBinding {
  predecessorToken: string;
  predecessorId: string;
  successorId: string;
}

export function sealReplayToken(binding: ReplayBinding, successorToken: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', replayKey(binding.predecessorToken), iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  cipher.setAAD(associatedData(binding.predecessorId, binding.successorId));

  const ciphertext = Buffer.concat([cipher.update(successorToken, 'utf8'), cipher.final()]);

  return [FORMAT, iv, ciphertext, cipher.getAuthTag()]
    .map((part) => (typeof part === 'string' ? part : part.toString('base64url')))
    .join('.');
}

export function openReplayToken(binding: ReplayBinding, sealed: string): string | null {
  const [format, iv, ciphertext, tag] = sealed.split('.');

  if (format !== FORMAT || !iv || !ciphertext || !tag) return null;

  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      replayKey(binding.predecessorToken),
      Buffer.from(iv, 'base64url'),
      // Pinned, or a truncated tag would be accepted.
      { authTagLength: AUTH_TAG_LENGTH },
    );
    decipher.setAAD(associatedData(binding.predecessorId, binding.successorId));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));

    return Buffer.concat([
      decipher.update(Buffer.from(ciphertext, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return null;
  }
}
