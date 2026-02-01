/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

import { getSystemConfig } from '../config/getSystemConfig';

let cachedLimiter: ReturnType<typeof rateLimit> | null = null;
let cachedLimit: number | null = null;

export async function dynamicJWKSRateLimit(req: Request, res: Response, next: NextFunction) {
  const { rate_limit } = await getSystemConfig();

  const limit = rate_limit ?? 50;

  if (!cachedLimiter || cachedLimit !== limit) {
    cachedLimit = limit;

    cachedLimiter = rateLimit({
      windowMs: 1 * 60 * 1000,
      max: limit,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many requests, please try again later',
    });
  }

  return next();
}
