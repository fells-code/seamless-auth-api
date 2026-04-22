/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { RequestHandler } from 'express';

import { CookieType } from '../services/sessionService.js';
import { verifyBearerAuth } from './verifyBearerAuth.js';
import { verifyCookieAuth } from './verifyCookieAuth.js';

export type AuthAwareRequestHandler = RequestHandler & {
  seamlessAuthType?: CookieType;
};

export function getSecuritySchemeName(cookieType: CookieType): string {
  const mode = (process.env.AUTH_MODE || 'web').toLowerCase();

  if (mode === 'server') {
    return 'bearerAuth';
  }

  return cookieType === 'ephemeral' ? 'ephemeralCookieAuth' : 'accessCookieAuth';
}

export function attachAuthMiddleware(cookieType: CookieType = 'access') {
  const mode = (process.env.AUTH_MODE || 'web').toLowerCase();
  const handler = (
    mode === 'server' ? verifyBearerAuth : verifyCookieAuth(cookieType)
  ) as AuthAwareRequestHandler;

  handler.seamlessAuthType = cookieType;

  return handler;
}
