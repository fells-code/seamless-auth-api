/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { NextFunction, Request, Response } from 'express';

import { validateSession } from '../services/sessionService';
import { AuthenticatedRequest } from '../types/types';
import getLogger from '../utils/logger';

const logger = getLogger('verifyBearerAuth');

export async function verifyBearerAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    logger.error('Missing beartoken for authentication request');
    return res.status(401).json({ error: 'missing bearer token' });
  }

  const token = auth.slice(7);
  try {
    const user = await validateSession({ type: 'bearer', value: token });
    if (!user) {
      logger.error('No user found for service bearer token');
      return res.status(401).json({ error: 'unauthorized' });
    }
    (req as AuthenticatedRequest).user = user;
    next();
  } catch (err) {
    console.error('verifyBearerAuth failed:', err);
    res.status(401).json({ error: 'unauthorized' });
  }
}
