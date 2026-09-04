/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createHmac } from 'crypto';

import { User } from '../models/users.js';

/**
 * A decoy is the pre-auth principal `/login` hands back for an identifier that has no
 * usable account, so that the first response no longer separates "this account exists
 * and can sign in" from everything else.
 *
 * Everything about a decoy derives from one HMAC over the identifier, which buys three
 * properties the design needs:
 *
 * - **Stable.** The same unknown identifier yields the same subject on every attempt.
 *   A real identifier resolves to the same row every time, so a decoy that rerolled its
 *   subject would be the oracle all over again, one request later.
 * - **Unguessable.** The key never leaves the server, so a caller cannot tell a decoy
 *   subject from a real user id by inspecting it, and cannot mint one.
 * - **Stateless.** No decoy is stored to be looked up later. Probing an endpoint that
 *   answers for unknown identifiers must not let a caller fill a table, so everything a
 *   continuation needs is recomputed from the subject in the token.
 *
 * A decoy is recognised on the way back in by its subject not resolving to a user row,
 * not by a claim. A `decoy` claim would be readable by anyone who base64-decodes the
 * token, which is the whole point given away.
 */

const DECOY_SUBJECT_INFO = 'seamless-auth/decoy-subject';
const DECOY_EMAIL_INFO = 'seamless-auth/decoy-email';
const DECOY_PHONE_INFO = 'seamless-auth/decoy-phone';
const DECOY_OTP_INFO = 'seamless-auth/decoy-otp';
const DECOY_CREDENTIAL_INFO = 'seamless-auth/decoy-credential';
const DECOY_SHAPE_INFO = 'seamless-auth/decoy-shape';

/**
 * Mirrors `stateSecret()` in oauthService: prefer a dedicated secret, fall back to the
 * service token that production already requires, and refuse to invent one in
 * production. A decoy subject derived from a guessable key is not a decoy.
 */
function decoySecret() {
  const explicit = process.env.DECOY_SUBJECT_SECRET?.trim();
  if (explicit) return explicit;

  const serviceSecret = process.env.API_SERVICE_TOKEN?.trim();
  if (serviceSecret) return serviceSecret;

  if (process.env.NODE_ENV !== 'production') {
    return `dev-decoy-subject:${process.env.APP_ID ?? 'local'}`;
  }

  throw new Error('DECOY_SUBJECT_SECRET or API_SERVICE_TOKEN is required in production.');
}

function derive(info: string, value: string) {
  return createHmac('sha256', decoySecret()).update(`${info}:${value}`).digest();
}

/**
 * Formats 16 derived bytes as a v4 UUID. The version and variant nibbles are forced so
 * the result is indistinguishable from the `UUIDV4` the users table generates; a decoy
 * subject that failed a UUID version check would announce itself.
 */
function formatAsUuidV4(bytes: Buffer) {
  const uuid = Buffer.from(bytes.subarray(0, 16));

  uuid[6] = (uuid[6] & 0x0f) | 0x40;
  uuid[8] = (uuid[8] & 0x3f) | 0x80;

  const hex = uuid.toString('hex');

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

export type DecoyIdentifierType = 'email' | 'phone';

/**
 * The subject a given unknown identifier always maps to.
 *
 * The identifier is folded to the same normal form `/login` looks accounts up under, so
 * `Ada@Example.com` and `ada@example.com` cannot be distinguished by the subject they
 * produce, exactly as they cannot for a real account.
 */
export function decoySubjectFor(identifier: string, identifierType: DecoyIdentifierType) {
  return formatAsUuidV4(
    derive(DECOY_SUBJECT_INFO, `${identifierType}:${identifier.toLowerCase()}`),
  );
}

/**
 * A decoy carries a synthetic email and phone because the identity-keyed rate limiters
 * read `req.user.email` and `req.user.phone`. Left undefined they would fall back to an
 * IP bucket, so every unknown identifier probed from one address would share a counter
 * while every real one got its own, which is a working oracle built out of 429s.
 *
 * These are derived from the subject rather than carried from the identifier, so a
 * continuation request reconstructs them from the token alone.
 */
function decoyEmailFor(subject: string) {
  return `${derive(DECOY_EMAIL_INFO, subject).toString('hex').slice(0, 24)}@example.invalid`;
}

function decoyPhoneFor(subject: string) {
  const digits = derive(DECOY_PHONE_INFO, subject).readUInt32BE(0) % 10_000_000;

  return `+1555${digits.toString().padStart(7, '0')}`;
}

/**
 * The code a decoy's OTP "is". Nothing ever compares against it, since a decoy
 * verification always fails, but external delivery mode returns the generated code in
 * the response body and a decoy has to put something of the right shape there.
 */
export function decoyOtpFor(subject: string) {
  return (derive(DECOY_OTP_INFO, subject).readUInt32BE(0) % 1_000_000).toString().padStart(6, '0');
}

/**
 * A credential id for the fabricated allow-list a decoy's WebAuthn challenge offers.
 * Base64url of 32 bytes, matching what a real credential id looks like on the wire.
 */
export function decoyCredentialIdFor(subject: string) {
  return derive(DECOY_CREDENTIAL_INFO, subject).toString('base64url');
}

/**
 * The stand-in `req.user` a decoy request carries.
 *
 * It is shaped like a `User` so that middleware reading `req.user.email` keeps working,
 * but it is a plain object and not a model instance: nothing on it can be saved. The
 * invariant that makes that safe is enforced in `defineRoute`, which routes a decoy
 * request to the route's decoy responder and never to the real handler. A route that
 * requires an ephemeral token and declares no decoy responder throws at registration,
 * which `tests/unit/lib/defineRouteDecoy.spec.ts` covers.
 */
export interface DecoyPrincipal {
  id: string;
  email: string;
  phone: string | null;
  roles: string[];
  verified: true;
  emailVerified: true;
  phoneVerified: true;
  revoked: false;
  /**
   * Whether this decoy "has" a passkey, for the purpose of the method list `/login`
   * offers.
   *
   * Not always true, which is the point. `loginMethods` is filtered by what an account
   * can actually do, so a decoy that always claimed the full set would make any narrower
   * set proof that a real account exists: an account with no passkey is offered
   * `magic_link` and `email_otp` and nothing else, and no decoy would ever answer that
   * way. Deriving the shape from the subject means a narrow list is equally likely to be
   * a decoy, so one probe settles nothing.
   *
   * It is derived rather than random so the same identifier answers the same way every
   * time, for the same reason the subject is.
   */
  hasPasskey: boolean;
  /**
   * Whether the decoy's fabricated credential is PRF-capable. `/webauthn/login/start`
   * filters a real account's credentials by this and answers 401 when none survive, so a
   * decoy that was always capable would answer 200 where a real account answers 401.
   */
  prfCapable: boolean;
  /** Transports for the fabricated credential. A real one carries them; an offer without
   * them is its own tell. */
  transports: ('internal' | 'hybrid' | 'usb' | 'nfc' | 'ble')[];
}

/** One bit of the subject's derived shape, stable for the life of the identifier. */
function decoyShapeBit(subject: string, index: number) {
  return (derive(DECOY_SHAPE_INFO, subject)[index] & 1) === 1;
}

export function decoyPrincipalForSubject(subject: string): DecoyPrincipal {
  const hasPhone = decoyShapeBit(subject, 1);

  return {
    id: subject,
    email: decoyEmailFor(subject),
    // Null for some decoys so that an account with no phone, which is offered no
    // phone_otp, is not distinguishable from a decoy on that basis either.
    phone: hasPhone ? decoyPhoneFor(subject) : null,
    roles: [],
    verified: true,
    emailVerified: true,
    phoneVerified: true,
    revoked: false,
    hasPasskey: decoyShapeBit(subject, 0),
    prfCapable: decoyShapeBit(subject, 2),
    transports: decoyShapeBit(subject, 3) ? ['internal', 'hybrid'] : ['usb', 'nfc'],
  };
}

/**
 * Widens a decoy to the `User` the request types promise. Deliberately the only place
 * that cast happens, so grepping for it finds every route into the fiction.
 */
export function decoyPrincipalAsUser(principal: DecoyPrincipal) {
  return principal as unknown as User;
}
