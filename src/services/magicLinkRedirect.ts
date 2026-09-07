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

  // `magic_link_redirect_uris` is matched exactly when set, because it exists for
  // targets whose origin cannot be compared: a custom application scheme such as
  // `myapp://auth`, or a universal link on a host that should not also be a WebAuthn
  // origin. Empty by default, and an empty list falls back to comparing against
  // `origins`, so a deployment that sets nothing is unaffected.
  if (
    !allowedRedirect(requestedRedirectUri, config.magic_link_redirect_uris ?? [], config.origins)
  ) {
    throw new MagicLinkRedirectNotAllowedError();
  }

  // Set rather than appended: a caller is free to carry its own query, and a second
  // `token=` would leave which one wins up to whoever parses it.
  const url = new URL(requestedRedirectUri);
  url.searchParams.set('token', token);

  return url.toString();
}
