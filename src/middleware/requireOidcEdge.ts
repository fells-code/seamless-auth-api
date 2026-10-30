/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, RequestHandler, Response } from 'express';
import rateLimit from 'express-rate-limit';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { validateInternalServiceToken } from './authenticateServiceToken.js';
import { rateLimitsDisabled } from './rateLimitsDisabled.js';
import { TOO_MANY_REQUESTS_BODY } from './tooManyRequests.js';
import { extractServiceToken, SERVICE_TOKEN_HEADER } from './trustedClientContext.js';

export const OIDC_EDGE_SECURITY_SCHEME = 'serviceToken';

export type SecuritySchemeAwareHandler = RequestHandler & { seamlessSecurityScheme?: string };

async function oidcEdgeGuard(req: Request, res: Response, next: NextFunction) {
  const token = extractServiceToken(req.get(SERVICE_TOKEN_HEADER) ?? undefined);
  const decoded = token ? await validateInternalServiceToken(token, { logInvalid: true }) : null;

  if (!decoded?.sub || decoded.iss !== 'seamless-portal-api' || decoded.aud !== 'seamless-auth') {
    return res.status(401).json({ error: 'invalid_service_token' });
  }

  // The same body as an unmatched route, so a disabled provider is indistinguishable from
  // an API that predates it (ADR 0001, D13).
  const { oidc_provider_enabled, oidc_issuer } = await getSystemConfig();
  if (!oidc_provider_enabled || !oidc_issuer) {
    return res.status(404).json({ error: 'Not Found' });
  }

  return next();
}

/**
 * The only way into `/oidc/*`: the internal service token, and the provider switched on.
 * These routes serve the OpenID Provider service and never a browser or an SDK.
 */
export const requireOidcEdge = oidcEdgeGuard as SecuritySchemeAwareHandler;
requireOidcEdge.seamlessSecurityScheme = OIDC_EDGE_SECURITY_SCHEME;

// A fixed ceiling rather than a config key: it exists so a misbehaving edge cannot flood
// the store, and a correct one at sign-in rates stays far below it.
const PAYLOAD_WRITES_PER_MINUTE_PER_MODEL = 6000;

export const oidcPayloadWriteLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: PAYLOAD_WRITES_PER_MINUTE_PER_MODEL,
  keyGenerator: (req) => `oidc-payload:${String(req.params.model)}`,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
});
