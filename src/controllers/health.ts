/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getPackageVersion } from '../openapi/document.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('health');

export const healthCheck = (req: Request, res: Response) => {
  return res.status(200).json({ message: 'System up' });
};

export const version = (req: Request, res: Response) => {
  logger.info('Version information obtained.');
  return res.status(200).json({ message: getPackageVersion() });
};
