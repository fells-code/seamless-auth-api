/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { isInsecureDevModeActive } from '../config/devModeGuard.js';
import { getPackageVersion } from '../openapi/document.js';
import { getAuditHealth } from '../services/auditHealth.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('health');

export const healthCheck = (req: Request, res: Response) => {
  const audit = getAuditHealth();
  const insecure = isInsecureDevModeActive();

  // Still 200: the service is serving requests, and a load balancer should not
  // pull it out for this. What changes is that an instance which has stopped
  // being able to record what it is doing, or that is running in development mode
  // on a public deployment, says so. Nothing is added to the body while healthy.
  if (!audit.degraded && !insecure) {
    return res.status(200).json({ message: 'System up' });
  }

  return res.status(200).json({
    message: audit.degraded ? 'System up, audit degraded' : 'System up, insecure configuration',
    degraded: {
      ...(audit.degraded
        ? { audit: { failureCount: audit.failureCount, lastFailureAt: audit.lastFailureAt } }
        : {}),
      ...(insecure ? { insecureDevelopmentMode: true as const } : {}),
    },
  });
};

export const version = (req: Request, res: Response) => {
  logger.info('Version information obtained.');
  return res.status(200).json({ message: getPackageVersion() });
};
