/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Session } from '../models/sessions.js';

export const DEFAULT_STEP_UP_MAX_AGE_SECONDS = 5 * 60;

export type StepUpMethod = 'webauthn' | 'totp';

export interface StepUpStatus {
  sessionFound: boolean;
  fresh: boolean;
  method: StepUpMethod | null;
  verifiedAt: Date | null;
  expiresAt: Date | null;
  maxAgeSeconds: number;
}

interface StepUpSessionFields {
  stepUpVerifiedAt?: Date | null;
  stepUpMethod?: StepUpMethod | string | null;
}

function expiresAt(verifiedAt: Date, maxAgeSeconds: number) {
  return new Date(verifiedAt.getTime() + maxAgeSeconds * 1000);
}

export function getStepUpStatusFromSession(
  session: StepUpSessionFields | null,
  maxAgeSeconds = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
  now = new Date(),
): StepUpStatus {
  if (!session) {
    return {
      sessionFound: false,
      fresh: false,
      method: null,
      verifiedAt: null,
      expiresAt: null,
      maxAgeSeconds,
    };
  }

  const verifiedAt = session.stepUpVerifiedAt ?? null;
  const method =
    session.stepUpMethod === 'webauthn' || session.stepUpMethod === 'totp'
      ? session.stepUpMethod
      : null;
  const stepUpExpiresAt = verifiedAt ? expiresAt(verifiedAt, maxAgeSeconds) : null;

  return {
    sessionFound: true,
    fresh: Boolean(verifiedAt && stepUpExpiresAt && stepUpExpiresAt.getTime() > now.getTime()),
    method,
    verifiedAt,
    expiresAt: stepUpExpiresAt,
    maxAgeSeconds,
  };
}

async function findCurrentSession(sessionId: string, userId: string) {
  return Session.findOne({
    where: {
      id: sessionId,
      userId,
      revokedAt: null,
    },
  });
}

export async function getSessionStepUpStatus({
  sessionId,
  userId,
  maxAgeSeconds = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
}: {
  sessionId: string;
  userId: string;
  maxAgeSeconds?: number;
}) {
  const session = await findCurrentSession(sessionId, userId);

  return getStepUpStatusFromSession(session, maxAgeSeconds);
}

export async function recordStepUpVerification({
  sessionId,
  userId,
  method,
  verifiedAt = new Date(),
  maxAgeSeconds = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
}: {
  sessionId: string;
  userId: string;
  method: StepUpMethod;
  verifiedAt?: Date;
  maxAgeSeconds?: number;
}) {
  const session = await findCurrentSession(sessionId, userId);

  if (!session) {
    return null;
  }

  session.stepUpVerifiedAt = verifiedAt;
  session.stepUpMethod = method;
  await session.save();

  return getStepUpStatusFromSession(session, maxAgeSeconds, verifiedAt);
}

export function serializeStepUpStatus(status: StepUpStatus) {
  return {
    fresh: status.fresh,
    method: status.method,
    verifiedAt: status.verifiedAt?.toISOString() ?? null,
    expiresAt: status.expiresAt?.toISOString() ?? null,
    maxAgeSeconds: status.maxAgeSeconds,
  };
}
