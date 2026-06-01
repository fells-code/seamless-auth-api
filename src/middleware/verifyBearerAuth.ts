/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';

import { AuthTokenType, validateBearerToken } from '../services/sessionService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('verifyBearerAuth');

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
      return res.status(401).json({ error: 'unauthorized' });
    }
    (req as AuthenticatedRequest).user = result.user;
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
