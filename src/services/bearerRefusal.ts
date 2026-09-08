/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthTokenType, verifyJwtWithKid } from './sessionService.js';

export interface MisusedBearer {
  presentedType: string;
  subject: string | null;
}

/**
 * The `typ` a bearer claims, read without verifying anything.
 *
 * This only decides whether a refusal is worth a second verification. A token whose
 * claimed type is the one the gate asked for cannot be a type mismatch however it is
 * signed, and that covers the ordinary refusals (an expired access token, a rotated
 * session), which would otherwise pay for a verification that can only conclude there
 * is nothing to record. The event itself is built from the verified payload.
 */
function peekTokenType(token: string): string | null {
  const segment = token.split('.')[1];

  if (!segment) return null;

  try {
    const claims: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));

    if (!claims || typeof claims !== 'object') return null;

    const typ = (claims as Record<string, unknown>).typ;

    return typeof typ === 'string' ? typ : null;
  } catch {
    return null;
  }
}

/**
 * Identifies a bearer this issuer minted that was presented at a gate it does not open.
 *
 * Deliberately narrower than "the request was refused". A missing, malformed, expired
 * or unsigned credential is something any caller can produce for free, so recording
 * those would let one scanner, or one signing key rotation, fill `auth_events` with
 * rows that name no attacker and bury the ones that do. A token of the wrong type had
 * to be issued by this server first, which bounds the volume to real flows and makes
 * the row worth reading: it is an ephemeral token, which proves possession of an
 * address and nothing else, being offered where an access session is required.
 */
export async function findMisusedBearer(
  token: string,
  expectedType: AuthTokenType,
): Promise<MisusedBearer | null> {
  const claimedType = peekTokenType(token);

  if (claimedType === null || claimedType === expectedType) {
    return null;
  }

  const payload = await verifyJwtWithKid(token);

  if (!payload || typeof payload.typ !== 'string' || payload.typ === expectedType) {
    return null;
  }

  return {
    presentedType: payload.typ,
    subject: typeof payload.sub === 'string' ? payload.sub : null,
  };
}
