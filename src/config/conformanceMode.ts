/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

// The FIDO2 conformance test tools drive a server through a fixed message
// interface that skips this API's own pre-auth flow, mints no sessions, and is
// expected to accept deliberately malformed input. That surface has no business
// existing in a customer deployment, so it is mounted only when
// FIDO_CONFORMANCE_MODE is "true", and refused outright under a production
// NODE_ENV (mirrors DISABLE_AUTH_RATE_LIMITS and
// ALLOW_UNCREDENTIALED_DELIVERY_SECRETS).
export function conformanceModeEnabled(): boolean {
  if (process.env.FIDO_CONFORMANCE_MODE !== 'true') {
    return false;
  }

  return process.env.NODE_ENV !== 'production';
}
