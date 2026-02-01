/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request, Response } from 'express';

import getLogger from '../utils/logger';

const logger = getLogger('health');

export const healthCheck = (req: Request, res: Response) => {
  return res.status(200).json({ message: 'System up' });
};

export const version = (req: Request, res: Response) => {
  logger.info('Version information obtained.');
  return res.status(200).json({ message: process.env.VERSION });
};
