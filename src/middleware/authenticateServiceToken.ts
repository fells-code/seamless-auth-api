/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { NextFunction, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

import { ServiceRequest } from '../types/types';
import getLogger from '../utils/logger';
import { getSecret } from '../utils/secretsStore';

const logger = getLogger('authenticateServiceToken');

export async function verifyServiceToken(req: ServiceRequest, res: Response, next: NextFunction) {
  const JWT_INTERNAL = await getSecret('SEAMLESS_INTERNAL_TOKEN');
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    logger.error(`Call to internal endpoints missing bearer token. Headers: ${req.headers}`);
    return res.status(401).json({ error: 'No token provided' });
  }

  if (!JWT_INTERNAL) {
    logger.error('Call to internal endpoints missing M2M token.');
    return res.status(401).json({ message: 'Failed to pull api to api token' });
  }

  try {
    const decoded = jwt.verify(token, JWT_INTERNAL) as JwtPayload;

    if (decoded.iss !== 'seamless-portal-api') {
      logger.error('Improperly formed token detected.');
      return res.status(403).json({ error: 'Invalid token issuer' });
    }

    req.clientId = decoded.sub;
    req.triggeredBy = req.params.triggeredBy;
    next();
  } catch (error: unknown) {
    logger.error(`An error occured validating api to api service. ${error}`);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
