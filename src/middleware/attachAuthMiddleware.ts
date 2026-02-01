/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { CookieType } from '../services/sessionService';
import { verifyBearerAuth } from './verifyBearerAuth';
import { verifyCookieAuth } from './verifyCookieAuth';

export function attachAuthMiddleware(cookieType: CookieType = 'access') {
  const mode = (process.env.AUTH_MODE || 'web').toLowerCase();
  return mode === 'server' ? verifyBearerAuth : verifyCookieAuth(cookieType);
}
