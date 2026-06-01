/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import { getSecret } from '../utils/secretsStore.js';

const logger = getLogger('authenticateServiceToken');

let cachedSecret: string | null = null;

async function getInternalSecret() {
  if (cachedSecret) return cachedSecret;
  cachedSecret = await getSecret('API_SERVICE_TOKEN');
  return cachedSecret;
}

export async function validateInternalServiceToken(token: string): Promise<JwtPayload | null> {
  const internalSecret = await getInternalSecret();

  if (!token || !internalSecret) {
    return null;
  }

  try {
    return jwt.verify(token, internalSecret) as JwtPayload;
  } catch (error: unknown) {
    logger.error(`An error occured validating api to api service. ${error}`);
    return null;
  }
}

export async function verifyServiceToken(req: ServiceRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Malformed authorization header' });
  }

  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    logger.error('Call to internal endpoints missing bearer token.');
    return res.status(401).json({ error: 'No token provided' });
  }

  const decoded = await validateInternalServiceToken(token);

  if (!decoded) {
    logger.error('Call to internal endpoints missing M2M token.');
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (decoded.iss !== 'seamless-portal-api') {
    logger.error('Improperly formed token detected.');
    return res.status(403).json({ error: 'Invalid token issuer' });
  }

  if (decoded.aud !== 'seamless-auth') {
    return res.status(403).json({ error: 'Invalid audience' });
  }

  req.clientId = decoded.sub;
  req.triggeredBy = req.params.triggeredBy;
  next();
}
