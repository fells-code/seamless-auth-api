/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
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

export function attachAuthMiddleware(
  authType: AuthTokenType = 'access',
  options: { allowRecoverySession?: boolean } = {},
) {
  const handler = ((req, res, next) =>
    verifyBearerAuth(req, res, next, authType, options)) as AuthAwareRequestHandler;

  handler.seamlessAuthType = authType;

  return handler;
}
