/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { AuthenticatedRequest } from '../types/types.js';

let dynamicLimiter: ReturnType<typeof rateLimit> | null = null;
let dynamicLimit: number | null = null;
let magicLinkIpCachedLimiter: ReturnType<typeof rateLimit> | null = null;
let magicLinkIdentityCachedLimiter: ReturnType<typeof rateLimit> | null = null;

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

export async function dynamicRateLimit(req: Request, res: Response, next: NextFunction) {
  const { rate_limit } = await getSystemConfig();

  const limit = rate_limit ?? 50;

  if (!dynamicLimiter || dynamicLimit !== limit) {
    dynamicLimit = limit;

    dynamicLimiter = rateLimit({
      windowMs: 1 * 60 * 1000,
      max: limit,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many requests, please try again later',
    });
  }

  return dynamicLimiter(req, res, next);
}

export async function magicLinkIpLimiter(req: Request, res: Response, next: NextFunction) {
  if (!magicLinkIpCachedLimiter) {
    magicLinkIpCachedLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 20,
      standardHeaders: true,
      legacyHeaders: false,
    });
  }

  return magicLinkIpCachedLimiter(req, res, next);
}

export async function magicLinkEmailLimiter(req: Request, res: Response, next: NextFunction) {
  if (!magicLinkIdentityCachedLimiter) {
    magicLinkIdentityCachedLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5,
      keyGenerator: getMagicLinkIdentityKey,
      standardHeaders: true,
      legacyHeaders: false,
    });
  }

  return magicLinkIdentityCachedLimiter(req, res, next);
}
