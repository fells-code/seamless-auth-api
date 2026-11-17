/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Session, SessionAuthMethod } from '../models/sessions.js';
import { deriveAcrAmr } from './oidcAuthContext.js';

export const DEFAULT_STEP_UP_MAX_AGE_SECONDS = 5 * 60;

/** How recent a sign-in must be to add the first factor to an account that has none. */
export const FIRST_FACTOR_SIGN_IN_MAX_AGE_SECONDS = 10 * 60;

const MAX_SESSION_LINEAGE = 8;

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

export async function findCurrentSession(sessionId: string, userId: string) {
  return Session.findOne({
    where: {
      id: sessionId,
      userId,
      revokedAt: null,
    },
  });
}

function chainStart(session: Pick<Session, 'chainStartedAt' | 'createdAt'>) {
  return session.chainStartedAt ?? session.createdAt ?? null;
}

/**
 * When the human behind this session last signed in: the earliest chain start across the
 * session and the sessions it was exchanged from, since an exchanged child starts a chain
 * of its own. Null when any link is missing, which callers treat as no factor counting.
 */
export async function findSessionSignInTime(
  session: Pick<Session, 'chainStartedAt' | 'createdAt' | 'parentSessionId'>,
): Promise<Date | null> {
  let earliest = chainStart(session);
  let parentId = session.parentSessionId ?? null;

  for (let hops = 0; parentId; hops += 1) {
    if (!earliest || hops >= MAX_SESSION_LINEAGE) return null;

    const parent = await Session.findByPk(parentId);
    if (!parent) return null;

    const parentStart = chainStart(parent);
    if (!parentStart) return null;

    if (parentStart < earliest) earliest = parentStart;
    parentId = parent.parentSessionId ?? null;
  }

  return earliest;
}

/**
 * A factor proves the session's holder only if it was enrolled before that holder signed
 * in. One enrolled since could have been added by whoever holds the session's token, so
 * accepting it would let the token vouch for itself.
 */
export function factorPredatesSignIn(
  enrolledAt: Date | null | undefined,
  signedInAt: Date | null,
): boolean {
  return Boolean(enrolledAt && signedInAt && new Date(enrolledAt) < signedInAt);
}

/** The current session and when its holder signed in, for a step-up ceremony. */
export async function getStepUpSignInTime(sessionId: string, userId: string) {
  const session = await findCurrentSession(sessionId, userId);
  if (!session) return { sessionFound: false, signedInAt: null };

  return { sessionFound: true, signedInAt: await findSessionSignInTime(session) };
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
