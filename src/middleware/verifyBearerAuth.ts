/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';

import { AuthEventService } from '../services/authEventService.js';
import { findMisusedBearer } from '../services/bearerRefusal.js';
import { AuthTokenType, validateBearerToken } from '../services/sessionService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('verifyBearerAuth');

/** The matched route pattern, so path parameters do not turn one route into many. */
function routeLabel(req: Request): string {
  const pattern = typeof req.route?.path === 'string' ? req.route.path : req.path;

  return `${req.baseUrl ?? ''}${pattern ?? ''}`;
}

/**
 * Records a refusal that a token this server issued caused.
 *
 * The subject is metadata rather than `userId`: a refused token has established no
 * principal, and an ephemeral subject may be the decoy `/login` mints for an address
 * with no account, which resolves to no row at all.
 *
 * Written server side and never reflected to the caller, so the refusal it describes
 * answers exactly as it did before.
 */
async function recordBearerMisuse(req: Request, token: string, expectedType: AuthTokenType) {
  const misuse = await findMisusedBearer(token, expectedType);

  if (!misuse) return;

  await AuthEventService.log({
    type: 'bearer_token_failed',
    req,
    metadata: {
      reason: 'wrong_token_type',
      expected: expectedType,
      presented: misuse.presentedType,
      route: routeLabel(req),
      subject: misuse.subject,
    },
  });
}

export async function verifyBearerAuth(
  req: Request,
  res: Response,
  next: NextFunction,
  authType: AuthTokenType = 'access',
) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    logger.error('Missing bearer token for authentication request');
    return res.status(401).json({ error: 'missing bearer token' });
  }

  const token = auth.slice(7);
  try {
    const result = await validateBearerToken(token, authType);
    if (!result) {
      logger.error(`Invalid ${authType} bearer token`);
      await recordBearerMisuse(req, token, authType);
      return res.status(401).json({ error: 'unauthorized' });
    }
    (req as AuthenticatedRequest).user = result.user;
    if (result.decoy) {
      (req as AuthenticatedRequest).decoy = true;
    }
    if (result.sessionId !== undefined) {
      (req as AuthenticatedRequest).sessionId = result.sessionId;
    }
    if (result.organizationId !== undefined) {
      (req as AuthenticatedRequest).organizationId = result.organizationId;
    }
    next();
  } catch (err) {
    logger.error(`verifyBearerAuth failed: ${err}`);
    res.status(401).json({ error: 'unauthorized' });
  }
}
