/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * The full WebAuthn transport set, matching SimpleWebAuthn's
 * `AuthenticatorTransportFuture`, which is what registration actually stores.
 *
 * The older four-value set (usb, ble, nfc, internal) predates hybrid transport. A
 * cross-device passkey, a phone authenticating a desktop browser, reports `hybrid`,
 * older Chrome reported `cable`, and security keys can report `smart-card`. Narrowing
 * to the old four silently emptied `transports` for those credentials on the way out,
 * even though the stored value was correct.
 *
 * `@seamless-auth/types` widens `CredentialApiSchema.transports` to this same set in
 * its next release. Once this repo picks that up, this module and the local schema
 * override in `credential.responses.ts` can both go away.
 */
export const AUTHENTICATOR_TRANSPORTS = [
  'ble',
  'cable',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb',
] as const;

export type AuthenticatorTransport = (typeof AUTHENTICATOR_TRANSPORTS)[number];
