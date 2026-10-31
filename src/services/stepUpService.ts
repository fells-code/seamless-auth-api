/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Session, SessionAuthMethod } from '../models/sessions.js';

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

function stepUpAuthMethod(
  method: StepUpMethod,
  at: Date,
  passkey: { deviceBound: boolean; userVerified: boolean } | undefined,
): SessionAuthMethod {
  return method === 'webauthn'
    ? {
        method: 'passkey',
        at: at.toISOString(),
        deviceBound: passkey?.deviceBound === true,
        userVerified: passkey?.userVerified === true,
      }
    : { method: 'totp', at: at.toISOString() };
}

/**
 * A repeat of a method the session already holds replaces that record with the newer time,
 * so the list stays bounded by the distinct ways a user can authenticate.
 */
export function mergeAuthMethod(
  existing: readonly SessionAuthMethod[],
  record: SessionAuthMethod,
): SessionAuthMethod[] {
  const sameKind = (other: SessionAuthMethod) =>
    other.method === record.method &&
    other.deviceBound === record.deviceBound &&
    other.userVerified === record.userVerified;

  return [...existing.filter((other) => !sameKind(other)), record];
}

/**
 * Step-up is an authentication, so besides the first-party freshness window it adds the
 * method to the session's auth context and moves `authTime`, which is what the provider's
 * `amr`, `acr` and `auth_time` are derived from.
 */
export async function recordStepUpVerification({
  sessionId,
  userId,
  method,
  passkey,
  verifiedAt = new Date(),
  maxAgeSeconds = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
}: {
  sessionId: string;
  userId: string;
  method: StepUpMethod;
  passkey?: { deviceBound: boolean; userVerified: boolean };
  verifiedAt?: Date;
  maxAgeSeconds?: number;
}) {
  const session = await findCurrentSession(sessionId, userId);

  if (!session) {
    return null;
  }

  session.stepUpVerifiedAt = verifiedAt;
  session.stepUpMethod = method;
  session.authMethods = mergeAuthMethod(
    session.authMethods ?? [],
    stepUpAuthMethod(method, verifiedAt, passkey),
  );
  session.authTime = verifiedAt;
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
