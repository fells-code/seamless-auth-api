/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import type { AuthenticatorTransportFuture, Uint8Array_ } from '@simplewebauthn/server';

export type ConformancePurpose = 'registration' | 'authentication';

export interface ConformanceCredential {
  id: string;
  publicKey: Uint8Array_;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
}

export interface ConformanceUser {
  /** Stable WebAuthn user handle, so a re-registration keeps the same identity. */
  handle: Uint8Array_;
  username: string;
  displayName: string;
  credentials: ConformanceCredential[];
}

export interface PendingCeremony {
  purpose: ConformancePurpose;
  username: string;
  challenge: string;
  requireUserVerification: boolean;
  expiresAt: number;
}

/**
 * Everything the conformance interface knows, held in memory for the life of the
 * process.
 *
 * Deliberately not the `users` and `credentials` tables. The tools invent
 * hundreds of accounts, replay ceremonies, and send malformed input on purpose,
 * none of which belongs in the tables a real deployment authenticates against.
 * What the run is meant to exercise is the WebAuthn verification itself, and
 * that is the shipping library call with the shipping configuration, not a copy.
 */
const users = new Map<string, ConformanceUser>();

/**
 * Outstanding ceremonies, keyed by the challenge that was issued.
 *
 * The conformance API sends the username only on the options request, so a
 * result has to be matched back to its ceremony some other way. Every result
 * carries `clientDataJSON`, which carries the challenge, so the challenge is the
 * key. That avoids needing a session cookie on a surface that otherwise holds no
 * session state, and it makes a replay impossible for free: the entry is deleted
 * on lookup.
 */
const ceremonies = new Map<string, PendingCeremony>();

const CEREMONY_TTL_MS = 5 * 60 * 1000;

export function getConformanceUser(username: string): ConformanceUser | undefined {
  return users.get(username);
}

export function upsertConformanceUser(params: {
  username: string;
  displayName: string;
  handle: Uint8Array_;
}): ConformanceUser {
  const existing = users.get(params.username);

  if (existing) {
    existing.displayName = params.displayName;
    return existing;
  }

  const created: ConformanceUser = {
    handle: params.handle,
    username: params.username,
    displayName: params.displayName,
    credentials: [],
  };

  users.set(params.username, created);

  return created;
}

export function addConformanceCredential(username: string, credential: ConformanceCredential) {
  const user = users.get(username);

  if (!user) {
    return;
  }

  user.credentials = user.credentials.filter((existing) => existing.id !== credential.id);
  user.credentials.push(credential);
}

export function findConformanceCredential(
  credentialId: string,
): { user: ConformanceUser; credential: ConformanceCredential } | undefined {
  for (const user of users.values()) {
    const credential = user.credentials.find((entry) => entry.id === credentialId);

    if (credential) {
      return { user, credential };
    }
  }

  return undefined;
}

export function rememberCeremony(
  ceremony: Omit<PendingCeremony, 'expiresAt'>,
  now = Date.now(),
): void {
  pruneExpired(now);
  ceremonies.set(ceremony.challenge, { ...ceremony, expiresAt: now + CEREMONY_TTL_MS });
}

/** Takes a ceremony and spends it, so the same challenge cannot be answered twice. */
export function consumeCeremony(challenge: string, now = Date.now()): PendingCeremony | undefined {
  const ceremony = ceremonies.get(challenge);

  if (!ceremony) {
    return undefined;
  }

  ceremonies.delete(challenge);

  if (ceremony.expiresAt <= now) {
    return undefined;
  }

  return ceremony;
}

export function resetConformanceStore() {
  users.clear();
  ceremonies.clear();
}

function pruneExpired(now: number) {
  for (const [challenge, ceremony] of ceremonies) {
    if (ceremony.expiresAt <= now) {
      ceremonies.delete(challenge);
    }
  }
}
