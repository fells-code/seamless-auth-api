/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Response } from 'express';

import { hasScopedRole } from '../lib/scopedRoles.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';
import {
  type DeviceStepUpAwareHandler,
  refuseDeviceSessionWithoutStepUp,
} from './requireDeviceSessionStepUp.js';

const logger = getLogger('requireAdmin');

export type AdminAccessLevel = 'read' | 'write';

export function requireAdmin(accessLevel?: AdminAccessLevel) {
  const requiredRole = accessLevel ? `admin:${accessLevel}` : 'admin';

  const guard = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        logger.error('Admin route hit without authenticated user');
        return res.status(401).json({ error: 'Unauthorized' });
      }

      if (!hasScopedRole(req.user.roles, requiredRole)) {
        logger.warn(`User ${req.user.id} attempted admin access without ${requiredRole} role`);
        return res.status(403).json({ error: 'Forbidden' });
      }

      if (refuseDeviceSessionWithoutStepUp(req, res)) return;

      next();
    } catch (err) {
      logger.error(`requireAdmin failure: ${err}`);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  const handler = guard as typeof guard & DeviceStepUpAwareHandler;
  handler.seamlessDeviceStepUp = true;
  return handler;
}
