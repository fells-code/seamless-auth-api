/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { AuthenticatedRequest } from '../types/types.js';

async function getConfiguredRateLimit() {
  const { rate_limit } = await getSystemConfig();

  return rate_limit ?? 50;
}

function getMagicLinkIdentityKey(req: Request) {
  const authReq = req as AuthenticatedRequest;
  const body = req.body as { email?: unknown } | undefined;
  const query = req.query as { email?: unknown } | undefined;
  const email =
    authReq.user?.email ??
    (typeof body?.email === 'string' ? body.email : undefined) ??
    (typeof query?.email === 'string' ? query.email : undefined);

  if (email) {
    return `email:${email.toLowerCase()}`;
  }

  return `ip:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`;
}

const dynamicLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  limit: getConfiguredRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later',
});

const magicLinkIpCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const magicLinkIdentityCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyGenerator: getMagicLinkIdentityKey,
  standardHeaders: true,
  legacyHeaders: false,
});

export function dynamicRateLimit(req: Request, res: Response, next: NextFunction) {
  return dynamicLimiter(req, res, next);
}

export function magicLinkIpLimiter(req: Request, res: Response, next: NextFunction) {
  return magicLinkIpCachedLimiter(req, res, next);
}

export function magicLinkEmailLimiter(req: Request, res: Response, next: NextFunction) {
  return magicLinkIdentityCachedLimiter(req, res, next);
}
