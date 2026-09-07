/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';
import slowDown from 'express-slow-down';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { rateLimitsDisabled } from './rateLimitsDisabled.js';

async function getConfiguredDelayAfter() {
  const { delay_after } = await getSystemConfig();

  return delay_after ?? 25;
}

const cachedLimiter: ReturnType<typeof slowDown> = slowDown({
  windowMs: 1 * 60 * 1000,
  delayAfter: getConfiguredDelayAfter,
  legacyHeaders: false,
  // express-slow-down passes the total hits in the window, so multiplying that gave the
  // first throttled request a delay_after-second delay instead of one second. The excess
  // over the threshold is what should grow, and it is capped so a client that keeps
  // going cannot pin a handler for minutes.
  delayMs: (used, request) => (used - request.slowDown.limit) * 1000,
  maxDelayMs: 20000,
  skip: rateLimitsDisabled,
});

export function dynamicSlowDown(req: Request, res: Response, next: NextFunction) {
  return cachedLimiter(req, res, next);
}
