/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';
import rateLimit from 'express-rate-limit';

import { rateLimitsDisabled } from './rateLimitsDisabled.js';
import type { ApplicationRequest } from './requireApplicationToken.js';

const HOUR_MS = 60 * 60 * 1000;
const NOTICES_PER_CLIENT_PER_HOUR = 300;
const NOTICES_PER_USER_PER_CLIENT_PER_HOUR = 10;

const RATE_LIMITED = { error: 'notice_rate_limited' } as const;

function clientKey(req: Request) {
  return (req as ApplicationRequest).oidcClient?.id ?? 'unknown-client';
}

function limiter(limit: number, key: (req: Request) => string) {
  return rateLimit({
    windowMs: HOUR_MS,
    limit,
    keyGenerator: key,
    standardHeaders: true,
    legacyHeaders: false,
    skip: rateLimitsDisabled,
    message: RATE_LIMITED,
  });
}

export const applicationNoticeClientLimiter = limiter(NOTICES_PER_CLIENT_PER_HOUR, clientKey);

// The schema accepts an upper-case UUID and Postgres matches it case-insensitively, so the
// id is folded here or each case variant would get an allowance of its own.
function userKey(req: Request) {
  const userId = (req.body as { userId?: unknown })?.userId;

  return typeof userId === 'string' ? userId.toLowerCase() : String(userId);
}

// Per user within one client, so one application cannot spend another's allowance for the
// same user.
export const applicationNoticeUserLimiter = limiter(
  NOTICES_PER_USER_PER_CLIENT_PER_HOUR,
  (req) => `${clientKey(req)}:${userKey(req)}`,
);
