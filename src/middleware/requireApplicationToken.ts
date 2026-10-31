/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { seamlessBuiltInResource } from '@seamless-auth/types';
import { NextFunction, Request, Response } from 'express';
import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from 'jose';

import { getSystemConfig } from '../config/getSystemConfig.js';
import type { OidcClient } from '../models/oidcClients.js';
import { findActiveOidcClient } from '../services/oidcClientRegistry.js';
import { getOidcPublicJwks } from '../services/oidcProviderKeys.js';
import getLogger from '../utils/logger.js';
import type { SecuritySchemeAwareHandler } from './requireOidcEdge.js';

const logger = getLogger('requireApplicationToken');

export type ApplicationRequest = Request & { oidcClient?: OidcClient };

function bearer(req: Request) {
  const header = req.get('authorization');
  return header?.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : null;
}

/**
 * A client credentials token the provider service had the API sign, for the built-in
 * `<oidc_issuer>/seamless` resource with `scope` (ADR 0001, D14). `sub` must be the client
 * itself, so a user access token for the same resource does not qualify, and the client
 * must still be active and opted in when the token is used, not only when it was issued.
 */
export function requireApplicationToken(scope: string) {
  const guard = async (req: Request, res: Response, next: NextFunction) => {
    const refuse = () => res.status(401).json({ error: 'notice_invalid_token' });

    const token = bearer(req);
    const { oidc_issuer } = await getSystemConfig();
    if (!token || !oidc_issuer) return refuse();

    let claims;
    try {
      const jwks = createLocalJWKSet({ keys: getOidcPublicJwks().keys } as JSONWebKeySet);
      ({ payload: claims } = await jwtVerify(token, jwks, {
        issuer: oidc_issuer,
        audience: seamlessBuiltInResource(oidc_issuer),
        algorithms: ['RS256'],
        typ: 'at+jwt',
        clockTolerance: 30,
        requiredClaims: ['exp', 'sub', 'client_id', 'scope'],
      }));
    } catch (error) {
      logger.debug(`Application token refused: ${(error as Error).message}`);
      return refuse();
    }

    const scopes = typeof claims.scope === 'string' ? claims.scope.split(' ') : [];
    if (
      typeof claims.client_id !== 'string' ||
      claims.sub !== claims.client_id ||
      !scopes.includes(scope)
    ) {
      return refuse();
    }

    const client = await findActiveOidcClient(claims.client_id);
    if (!client || !client.grantTypes.includes('client_credentials')) return refuse();
    if (!client.noticesEnabled) {
      return res.status(403).json({ error: 'notice_not_enabled' });
    }

    (req as ApplicationRequest).oidcClient = client;
    return next();
  };

  const handler = guard as SecuritySchemeAwareHandler;
  handler.seamlessSecurityScheme = 'bearerAuth';
  return handler;
}
