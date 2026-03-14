/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { NextFunction, Request, Response } from 'express';

import getLogger from '../utils/logger.js';

const logger = getLogger('routeLogger');

export const logRoute = (req: Request, res: Response, next: NextFunction) => {
  logger.info(`Received ${req.method} request for ${req.url}`);
  next();
};
