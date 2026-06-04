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
const INTERNAL_SERVICE_TOKEN_ALGORITHMS = ['HS256', 'HS384', 'HS512'] as const;

interface InternalServiceTokenValidationOptions {
  logInvalid?: boolean;
}

function getJwtAlgorithm(token: string): string | null {
  const decoded = jwt.decode(token, { complete: true });

  if (!decoded || typeof decoded !== 'object') {
    return null;
  }

  const alg = (decoded as { header?: { alg?: unknown } }).header?.alg;

  return typeof alg === 'string' ? alg : null;
}

function usesSupportedInternalServiceAlgorithm(token: string) {
  const alg = getJwtAlgorithm(token);

  if (!alg) {
    return true;
  }

  return (INTERNAL_SERVICE_TOKEN_ALGORITHMS as readonly string[]).includes(alg);
}

async function getInternalSecret() {
  if (cachedSecret) return cachedSecret;
  cachedSecret = await getSecret('API_SERVICE_TOKEN');
  return cachedSecret;
}

export async function validateInternalServiceToken(
  token: string,
  options: InternalServiceTokenValidationOptions = {},
): Promise<JwtPayload | null> {
  const internalSecret = await getInternalSecret();

  if (!token || !internalSecret) {
    return null;
  }

  try {
    if (!usesSupportedInternalServiceAlgorithm(token)) {
      if (options.logInvalid) {
        logger.warn('Rejected internal service token with unsupported algorithm');
      }

      return null;
    }

    return jwt.verify(token, internalSecret, {
      algorithms: [...INTERNAL_SERVICE_TOKEN_ALGORITHMS],
    }) as JwtPayload;
  } catch (error: unknown) {
    if (options.logInvalid) {
      logger.error(`An error occured validating api to api service. ${error}`);
    }

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

  const decoded = await validateInternalServiceToken(token, { logInvalid: true });

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
