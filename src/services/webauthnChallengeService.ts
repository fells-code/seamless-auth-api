/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Op } from 'sequelize';

import { WebAuthnChallenge, type WebAuthnChallengePurpose } from '../models/webauthnChallenges.js';

/**
 * How long a challenge stays usable.
 *
 * Comfortably longer than the 60 second `timeout` in the credential options,
 * which is only a hint to the browser, so a user who takes a while to find a
 * security key or answer a biometric prompt is not cut off. Short enough that a
 * captured challenge is worth minutes rather than however long it took some
 * later flow to overwrite it.
 */
export const CHALLENGE_TTL_SECONDS = 300;

export interface IssuedChallenge {
  challenge: string;
  context: Record<string, unknown> | null;
}

/**
 * Records a challenge for one user and one flow.
 *
 * Any challenge still outstanding for the same user and flow is consumed first.
 * Only the newest matters, and leaving the older ones live would widen the
 * window a caller can replay against.
 *
 * Sign-in passes the attempt (the ephemeral token's `jti`), which narrows "the same
 * flow" to that attempt. A pre-auth token comes from an email address alone, so
 * without it anyone could start a ceremony for an account and replace the challenge
 * its owner is about to answer.
 */
export async function issueChallenge(params: {
  userId: string;
  purpose: WebAuthnChallengePurpose;
  challenge: string;
  context?: Record<string, unknown> | null;
  attemptId?: string;
  now?: Date;
}): Promise<WebAuthnChallenge> {
  const now = params.now ?? new Date();

  await consumeOutstanding(params.userId, params.purpose, params.attemptId, now);

  return WebAuthnChallenge.create({
    userId: params.userId,
    purpose: params.purpose,
    challenge: params.challenge,
    context: params.context ?? null,
    attemptId: params.attemptId ?? null,
    expiresAt: new Date(now.getTime() + CHALLENGE_TTL_SECONDS * 1000),
  });
}

/**
 * Takes the live challenge for one user and one flow, and spends it.
 *
 * Consuming on read rather than on success is deliberate: call this once at the
 * start of verification and the challenge is spent however the rest of the
 * attempt turns out, so a failed attempt cannot leave a live challenge behind
 * for someone to replay an assertion against.
 */
export async function consumeChallenge(params: {
  userId: string;
  purpose: WebAuthnChallengePurpose;
  attemptId?: string;
  now?: Date;
}): Promise<IssuedChallenge | null> {
  const now = params.now ?? new Date();

  const record = await WebAuthnChallenge.findOne({
    where: {
      userId: params.userId,
      purpose: params.purpose,
      ...(params.attemptId !== undefined ? { attemptId: params.attemptId } : {}),
      consumedAt: null,
      expiresAt: { [Op.gt]: now },
    },
    order: [['createdAt', 'DESC']],
  });

  if (!record) {
    return null;
  }

  // Conditional, so two verifications racing for one challenge cannot both spend it.
  const [spent] = await WebAuthnChallenge.update(
    { consumedAt: now },
    { where: { id: record.id, consumedAt: null } },
  );

  if (!spent) {
    return null;
  }

  return { challenge: record.challenge, context: record.context ?? null };
}

/**
 * Spends everything outstanding for a user, across every flow.
 *
 * Used when a different authentication route completes and any half-finished
 * WebAuthn ceremony should not still be redeemable.
 */
export async function invalidateChallengesForUser(userId: string, now = new Date()) {
  await WebAuthnChallenge.update(
    { consumedAt: now },
    {
      where: {
        userId,
        consumedAt: null,
      },
    },
  );
}

async function consumeOutstanding(
  userId: string,
  purpose: WebAuthnChallengePurpose,
  attemptId: string | undefined,
  now: Date,
) {
  await WebAuthnChallenge.update(
    { consumedAt: now },
    {
      where: {
        userId,
        purpose,
        ...(attemptId !== undefined ? { attemptId } : {}),
        consumedAt: null,
      },
    },
  );
}
