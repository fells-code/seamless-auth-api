/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { rateLimitsDisabled } from './rateLimitsDisabled.js';
import { TOO_MANY_REQUESTS_BODY } from './tooManyRequests.js';

async function getConfiguredRateLimit() {
  const { rate_limit } = await getSystemConfig();

  return rate_limit ?? 50;
}

const jwksLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  limit: getConfiguredRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: TOO_MANY_REQUESTS_BODY,
  skip: rateLimitsDisabled,
});

export function dynamicJWKSRateLimit(req: Request, res: Response, next: NextFunction) {
  return jwksLimiter(req, res, next);
}
