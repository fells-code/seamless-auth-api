/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

// Escape hatch for automated testing and conformance runs, where many auth
// requests come from a single IP and would otherwise trip the per-IP OTP,
// magic-link, registration, and OAuth limiters. When DISABLE_AUTH_RATE_LIMITS is
// "true" the limiters below skip. It is refused under a production NODE_ENV, so it
// can never weaken a deployed server (mirrors ALLOW_UNCREDENTIALED_DELIVERY_SECRETS).
export function rateLimitsDisabled(): boolean {
  if (process.env.DISABLE_AUTH_RATE_LIMITS !== 'true') {
    return false;
  }

  return process.env.NODE_ENV !== 'production';
}
