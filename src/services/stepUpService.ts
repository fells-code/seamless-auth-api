/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Session, SessionAuthMethod } from '../models/sessions.js';
import { deriveAcrAmr } from './oidcAuthContext.js';

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

const ACR_RANK = { phr: 1, phrh: 2 } as const;

function acrRank(authMethods: readonly SessionAuthMethod[]) {
  const { acr } = deriveAcrAmr(authMethods);
  return acr ? ACR_RANK[acr] : 0;
}

/**
 * Step-up is an authentication, so besides the first-party freshness window it adds the
 * method to the session's auth context, which the provider's `amr` and `acr` are derived
 * from. `authTime` moves only when the step-up alone earns at least the session's `acr`:
 * `auth_time` is read as when the authentication `acr` describes happened, so a fresh TOTP
 * must not make an hours-old passkey look recent.
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

  const record = stepUpAuthMethod(method, verifiedAt, passkey);
  const before = session.authMethods ?? [];

  session.stepUpVerifiedAt = verifiedAt;
  session.stepUpMethod = method;
  if (acrRank([record]) >= acrRank(before)) {
    session.authTime = verifiedAt;
  }
  session.authMethods = mergeAuthMethod(before, record);
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
