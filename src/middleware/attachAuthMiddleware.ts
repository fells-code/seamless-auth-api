/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { CookieType } from '../services/sessionService.js';
import { verifyBearerAuth } from './verifyBearerAuth.js';
import { verifyCookieAuth } from './verifyCookieAuth.js';

export function attachAuthMiddleware(cookieType: CookieType = 'access') {
  const mode = (process.env.AUTH_MODE || 'web').toLowerCase();
  return mode === 'server' ? verifyBearerAuth : verifyCookieAuth(cookieType);
}
