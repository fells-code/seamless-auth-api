/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Response } from 'express';

import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('requireAdmin');

export function requireAdmin() {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        logger.error('Admin route hit without authenticated user');
        return res.status(401).json({ error: 'Unauthorized' });
      }

      if (!req.user.roles?.includes('admin')) {
        logger.warn(`User ${req.user.id} attempted admin access without admin role`);
        return res.status(403).json({ error: 'Forbidden' });
      }

      next();
    } catch (err) {
      logger.error(`requireAdmin failure: ${err}`);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };
}
