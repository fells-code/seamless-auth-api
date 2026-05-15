/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';

import {
  DEFAULT_STEP_UP_MAX_AGE_SECONDS,
  getSessionStepUpStatus,
  serializeStepUpStatus,
} from '../services/stepUpService.js';
import { AuthenticatedRequest } from '../types/types.js';

export function requireStepUp(
  options: { maxAgeSeconds?: number } = {},
): (req: Request, res: Response, next: NextFunction) => Promise<void | Response> {
  const maxAgeSeconds = options.maxAgeSeconds ?? DEFAULT_STEP_UP_MAX_AGE_SECONDS;

  return async (req, res, next) => {
    const authReq = req as AuthenticatedRequest;
    const user = authReq.user;
    const sessionId = authReq.sessionId;

    if (!user?.id || !sessionId) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const status = await getSessionStepUpStatus({
      sessionId,
      userId: user.id,
      maxAgeSeconds,
    });

    if (!status.sessionFound) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    if (!status.fresh) {
      return res.status(403).json({
        error: 'step_up_required',
        message: 'Recent step-up authentication is required',
        ...serializeStepUpStatus(status),
      });
    }

    return next();
  };
}
