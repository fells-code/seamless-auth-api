/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';

import { getSystemConfig } from '../config/getSystemConfig';

let cachedLimiter: ReturnType<typeof rateLimit> | null = null;
let cachedLimit: number | null = null;

export async function dynamicSlowDown(req: Request, res: Response, next: NextFunction) {
  const { delay_after } = await getSystemConfig();

  const limit = delay_after ?? 25;

  if (!cachedLimiter || cachedLimit !== limit) {
    cachedLimit = limit;

    cachedLimiter = slowDown({
      windowMs: 1 * 60 * 1000,
      delayAfter: cachedLimit,
      legacyHeaders: false,
      delayMs: (hits) => hits * 1000,
      message: 'Too many requests, please try again later',
    });
  }

  return cachedLimiter(req, res, next);
}
