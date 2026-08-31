/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getPackageVersion } from '../openapi/document.js';
import { getAuditHealth } from '../services/auditHealth.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('health');

export const healthCheck = (req: Request, res: Response) => {
  const audit = getAuditHealth();

  // Still 200: the service is serving requests, and a load balancer should not
  // pull it out for this. What changes is that an instance which has stopped
  // being able to record what it is doing says so, which is the defined action
  // NIST 800-53 AU-5 asks for. Nothing is added to the body while healthy.
  if (audit.degraded) {
    return res.status(200).json({
      message: 'System up, audit degraded',
      degraded: {
        audit: {
          failureCount: audit.failureCount,
          lastFailureAt: audit.lastFailureAt,
        },
      },
    });
  }

  return res.status(200).json({ message: 'System up' });
};

export const version = (req: Request, res: Response) => {
  logger.info('Version information obtained.');
  return res.status(200).json({ message: getPackageVersion() });
};
