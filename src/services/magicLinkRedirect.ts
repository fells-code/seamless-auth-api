/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
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

export const DEFAULT_VERIFY_PATH = '/verify-magiclink';

function defaultLandingPages(origins: string[], frontendUrl?: string) {
  return [...new Set([frontendUrl, ...origins])]
    .filter((origin): origin is string => Boolean(origin))
    .map((origin) => `${origin.replace(/\/+$/, '')}${DEFAULT_VERIFY_PATH}`);
}

/**
 * Builds the link a magic link email points at.
 *
 * The token rides in the query and the code in the fragment. A fragment is never sent to
 * a server, never appears in a Referer, and is left out of most analytics, so a landing
 * page that leaks its query string leaks a lookup handle that cannot sign anyone in.
 *
 * Without a requested target this stays on the tenant-wide value it always used. A caller
 * that does ask is held to `magic_link_redirect_uris` when set, and otherwise to the
 * verify page on a configured origin. Matching on origin alone let a link land on any
 * page of the tenant's site, including one that forwards its URL somewhere else.
 */
export async function resolveMagicLinkUrl(
  token: string,
  code: string,
  requestedRedirectUri?: string,
) {
  const config = await getSystemConfig();
  const frontendUrl = config.frontend_url ?? config.origins[0];

  let url: URL;

  if (!requestedRedirectUri) {
    url = new URL(`${frontendUrl}${DEFAULT_VERIFY_PATH}`);
  } else {
    // Exact match in both cases. `magic_link_redirect_uris` exists for targets whose
    // origin cannot be compared, such as `myapp://auth` or a universal link on a host
    // that should not also be a WebAuthn origin.
    const configured = config.magic_link_redirect_uris ?? [];
    const allowed =
      configured.length > 0 ? configured : defaultLandingPages(config.origins, config.frontend_url);

    if (!allowedRedirect(requestedRedirectUri, allowed, [])) {
      throw new MagicLinkRedirectNotAllowedError();
    }

    url = new URL(requestedRedirectUri);
  }

  // Set rather than appended: a second `token=` would leave which one wins up to whoever
  // parses it. Any fragment the target carried is replaced for the same reason.
  url.searchParams.set('token', token);
  url.hash = new URLSearchParams({ code }).toString();

  return url.toString();
}
