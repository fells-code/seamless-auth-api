/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import type { Uint8Array_ } from '@simplewebauthn/server';
import { decodeAttestationObject } from '@simplewebauthn/server/helpers';

/**
 * How a credential identified itself, in the terms WebAuthn uses.
 *
 * - `none`: no statement. The authenticator said nothing about what it is.
 * - `self`: the statement is signed by the credential's own key, so it asserts
 *   an identity with nothing behind it. Anyone can produce one.
 * - `basic`: the statement is signed by an attestation key with a certificate
 *   chain, which is the only kind that can be traced back to a manufacturer.
 */
export type AttestationType = 'none' | 'self' | 'basic';

/**
 * Classifies a verified attestation statement.
 *
 * The distinction that matters is whether a certificate chain was presented,
 * because that is the only form the FIDO Metadata Service can be consulted for.
 * Every format except `packed` requires one, and refuses to verify without it
 * (`android-safetynet` carries its chain in the JWS header rather than `x5c`).
 * `packed` is the one format that is also defined without a chain, and that is
 * self attestation.
 *
 * A statement that cannot be decoded is reported as `self` rather than `basic`.
 * It has already passed verification by this point, so the question is only how
 * much it proves, and the answer for something unreadable is the lower one.
 */
export function classifyAttestation(
  fmt: string | undefined,
  attestationObject: Uint8Array_ | undefined,
): AttestationType {
  if (!fmt || fmt === 'none') {
    return 'none';
  }

  if (fmt !== 'packed') {
    return 'basic';
  }

  if (!attestationObject) {
    return 'self';
  }

  try {
    const decoded = decodeAttestationObject(attestationObject);
    return decoded.get('attStmt').get('x5c') ? 'basic' : 'self';
  } catch {
    return 'self';
  }
}
