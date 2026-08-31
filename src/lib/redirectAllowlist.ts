/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * Where a flow is allowed to send a browser or an app after it completes.
 *
 * One implementation for every flow that takes a redirect target from the caller. An
 * open redirect in an auth server hands an attacker a link on the tenant's own domain
 * that lands wherever they choose, which is worth having in one reviewable place rather
 * than once per flow.
 */

function parseUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

export function sameOrigin(value: string, allowedOrigin: string) {
  const parsedValue = parseUrl(value);
  const parsedAllowedOrigin = parseUrl(allowedOrigin);

  if (!parsedValue || !parsedAllowedOrigin) return false;

  return parsedValue.origin === parsedAllowedOrigin.origin;
}

/**
 * An explicit allowlist is matched exactly, because that is the only way to express a
 * target whose origin cannot be derived from a configured web origin: a mobile universal
 * link on a different host, or a custom scheme. Falling back to origin comparison only
 * when no allowlist is configured keeps an instance that has never set one working as it
 * did.
 */
export function allowedRedirect(value: string, allowedValues: string[], fallbackOrigins: string[]) {
  if (!parseUrl(value)) return false;

  if (allowedValues.length > 0) {
    return allowedValues.some((allowedValue) => value === allowedValue);
  }

  return fallbackOrigins.some((origin) => sameOrigin(value, origin));
}
