/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { RequestHandler } from 'express';

import { AuthTokenType } from '../services/sessionService.js';
import { verifyBearerAuth } from './verifyBearerAuth.js';

export type AuthAwareRequestHandler = RequestHandler & {
  seamlessAuthType?: AuthTokenType;
};

export function getSecuritySchemeName(_authType: AuthTokenType): string {
  return 'bearerAuth';
}

export function attachAuthMiddleware(authType: AuthTokenType = 'access') {
  const handler = verifyBearerAuth as AuthAwareRequestHandler;

  handler.seamlessAuthType = authType;

  return handler;
}
