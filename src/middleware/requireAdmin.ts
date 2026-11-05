/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Response } from 'express';

import { hasScopedRole } from '../lib/scopedRoles.js';
import { getStepUpStatusFromSession, serializeStepUpStatus } from '../services/stepUpService.js';
import { AuthenticatedRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('requireAdmin');

export type AdminAccessLevel = 'read' | 'write';

export function requireAdmin(accessLevel?: AdminAccessLevel) {
  const requiredRole = accessLevel ? `admin:${accessLevel}` : 'admin';

  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        logger.error('Admin route hit without authenticated user');
        return res.status(401).json({ error: 'Unauthorized' });
      }

      if (!hasScopedRole(req.user.roles, requiredRole)) {
        logger.warn(`User ${req.user.id} attempted admin access without ${requiredRole} role`);
        return res.status(403).json({ error: 'Forbidden' });
      }

      // ADR 0003, X7. Someone who phished a device approval holds a session like this without
      // holding the user's factor, so even a read waits for one (RFC 8628 section 5.4).
      if (req.deviceChildSession) {
        const status = getStepUpStatusFromSession(req.deviceChildSession);

        if (!status.fresh) {
          return res.status(403).json({
            error: 'step_up_required',
            message: 'Recent step-up authentication is required',
            ...serializeStepUpStatus(status),
          });
        }
      }

      next();
    } catch (err) {
      logger.error(`requireAdmin failure: ${err}`);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };
}
