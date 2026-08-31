/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { getSystemConfig } from '../config/getSystemConfig.js';
import { allowedRedirect } from '../lib/redirectAllowlist.js';

export class MagicLinkRedirectNotAllowedError extends Error {
  constructor() {
    super('Magic link redirect URI is not allowed');
    this.name = 'MagicLinkRedirectNotAllowedError';
  }
}

const DEFAULT_VERIFY_PATH = '/verify-magiclink';

/**
 * Builds the link a magic link email points at.
 *
 * Without a requested target this stays on the tenant-wide value it always used, so an
 * instance that asks for nothing sees no change. A caller that does ask is validated the
 * same way OAuth validates its redirect URI, against the configured origins, which is
 * what lets a tenant's web and mobile clients each receive a link that lands in the right
 * place rather than sharing one destination.
 */
export async function resolveMagicLinkUrl(token: string, requestedRedirectUri?: string) {
  const config = await getSystemConfig();

  if (!requestedRedirectUri) {
    const frontendUrl = config.frontend_url ?? config.origins[0];
    return `${frontendUrl}${DEFAULT_VERIFY_PATH}?token=${token}`;
  }

  // No dedicated allowlist yet, so the configured origins are the allowlist. See the
  // note in docs/api-contract.md: a target that cannot be expressed as one of those,
  // such as a custom scheme, needs a system config key that lives in
  // @seamless-auth/types and a coordinated release.
  if (!allowedRedirect(requestedRedirectUri, [], config.origins)) {
    throw new MagicLinkRedirectNotAllowedError();
  }

  // Set rather than appended: a caller is free to carry its own query, and a second
  // `token=` would leave which one wins up to whoever parses it.
  const url = new URL(requestedRedirectUri);
  url.searchParams.set('token', token);

  return url.toString();
}
