/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { OidcAcrValue, OidcAmrValue, OidcAuthContext } from '@seamless-auth/types';

import { Session, SessionAuthMethod } from '../models/sessions.js';
import { validateSessionRecord } from './sessionService.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Row ids are UUID columns, so anything else is answered as absent instead of a query error. */
export function isUuid(value: string) {
  return UUID_PATTERN.test(value);
}

const AMR_ORDER: readonly OidcAmrValue[] = ['hwk', 'swk', 'user', 'otp', 'sms', 'mfa'];

// A chain is only as long as the session's refreshes, so this is a guard against a
// corrupt link loop rather than a limit a real chain approaches.
const MAX_CHAIN_STEPS = 10_000;

/**
 * ADR 0001, D9. Passkeys map to `hwk` or `swk` by the backup eligibility the authenticator
 * reported, with `user` and `mfa` when it verified the user. Two distinct methods in one
 * session add `mfa`. Only a user-verified passkey earns an acr.
 */
export function deriveAcrAmr(authMethods: readonly SessionAuthMethod[]): {
  acr: OidcAcrValue | null;
  amr: OidcAmrValue[];
} {
  const amr = new Set<OidcAmrValue>();
  let acr: OidcAcrValue | null = null;

  for (const record of authMethods) {
    switch (record.method) {
      case 'passkey':
        amr.add(record.deviceBound ? 'hwk' : 'swk');
        if (record.userVerified) {
          amr.add('user');
          amr.add('mfa');
          acr = record.deviceBound || acr === 'phrh' ? 'phrh' : 'phr';
        }
        break;
      case 'phone_otp':
        amr.add('sms');
        amr.add('otp');
        break;
      case 'email_otp':
      case 'magic_link':
      case 'totp':
        amr.add('otp');
        break;
      default:
        break;
    }
  }

  if (new Set(authMethods.map((record) => record.method)).size >= 2) {
    amr.add('mfa');
  }

  return { acr, amr: AMR_ORDER.filter((value) => amr.has(value)) };
}

/**
 * The provider stores the session row its sign-in produced, and the edge's own adapter
 * rotates that row on every refresh. So the recorded id is followed forward through
 * `replacedBySessionId` to the row that is current now, and only that row is checked for
 * liveness. Revoking the chain, or the current row, ends provider access.
 */
export async function resolveCurrentSession(sessionId: string): Promise<Session | null> {
  if (!isUuid(sessionId)) return null;

  let current = await Session.findByPk(sessionId);
  let steps = 0;

  while (current?.replacedBySessionId && !current.revokedAt && steps < MAX_CHAIN_STEPS) {
    current = await Session.findByPk(current.replacedBySessionId);
    steps += 1;
  }

  if (!current) return null;

  return validateSessionRecord(current.id);
}

/**
 * When the session last authenticated, as epoch seconds. Rows from before the auth context
 * columns fall back to the start of the chain, so a refresh cannot make the sign-in look
 * more recent than it was.
 */
export function sessionAuthTime(session: Session) {
  return Math.floor(
    new Date(session.authTime ?? session.chainStartedAt ?? session.createdAt).getTime() / 1000,
  );
}

export async function getOidcAuthContext(sessionId: string): Promise<OidcAuthContext | null> {
  if (!isUuid(sessionId)) return null;

  const recorded = await Session.findByPk(sessionId);

  if (!recorded) return null;

  const current = await resolveCurrentSession(sessionId);
  // Step-up writes to the row the access token names, which after a refresh is a later
  // row than the one the provider recorded. Reading the current row is also what
  // /oidc/sign checks against, so the context the edge copies is the one it will accept.
  const source = current ?? recorded;
  const authMethods = source.authMethods ?? [];
  const { acr, amr } = deriveAcrAmr(authMethods);

  return {
    sessionId: recorded.id,
    userId: recorded.userId,
    active: current !== null,
    recovery: source.recovery === true,
    authMethods,
    authTime: sessionAuthTime(source),
    acr,
    amr,
  };
}
