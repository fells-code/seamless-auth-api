/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { DefaultFlowRateLimits } from '@seamless-auth/types';
import { NextFunction, Request, Response } from 'express';
import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { AuthenticatedRequest } from '../types/types.js';
import { rateLimitsDisabled } from './rateLimitsDisabled.js';
import { TOO_MANY_REQUESTS_BODY } from './tooManyRequests.js';

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

function getOtpIdentityKey(req: Request) {
  const authReq = req as AuthenticatedRequest;
  const body = req.body as { email?: unknown; phone?: unknown } | undefined;
  const email = authReq.user?.email ?? (typeof body?.email === 'string' ? body.email : undefined);
  const phone = authReq.user?.phone ?? (typeof body?.phone === 'string' ? body.phone : undefined);

  if (email) {
    return `email:${email.toLowerCase()}`;
  }

  if (phone) {
    return `phone:${phone}`;
  }

  return `ip:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`;
}

function getOAuthFlowKey(req: Request) {
  return [
    req.params?.providerId ?? 'unknown-provider',
    req.ip ?? req.socket.remoteAddress ?? 'unknown',
  ].join(':');
}

const dynamicLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  limit: getConfiguredRateLimit,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
});

/**
 * The per-flow limiters read their values from `flow_rate_limits` in system
 * config rather than carrying constants, because the right per-IP value differs
 * by audience: mobile carriers put thousands of subscribers behind one address,
 * so a limit that never troubles a web audience refuses a mobile one.
 *
 * `express-rate-limit` takes the limit as a function but the window only as a
 * number, so one limiter is built per configured window and kept. Changing the
 * window starts fresh counters; changing a limit takes effect on the next hit.
 */
type FlowRateLimits = NonNullable<Awaited<ReturnType<typeof getSystemConfig>>['flow_rate_limits']>;

async function getFlowRateLimits(): Promise<FlowRateLimits> {
  const { flow_rate_limits } = await getSystemConfig();

  return flow_rate_limits ?? DefaultFlowRateLimits;
}

function createFlowLimiter(
  pick: (limits: FlowRateLimits) => number,
  keyGenerator?: (req: Request) => string,
) {
  const byWindow = new Map<number, RateLimitRequestHandler>();

  return async function flowLimiter(req: Request, res: Response, next: NextFunction) {
    const windowMs = (await getFlowRateLimits()).windowSeconds * 1000;

    let limiter = byWindow.get(windowMs);
    if (!limiter) {
      limiter = rateLimit({
        windowMs,
        limit: async () => pick(await getFlowRateLimits()),
        ...(keyGenerator ? { keyGenerator } : {}),
        standardHeaders: true,
        legacyHeaders: false,
        skip: rateLimitsDisabled,
        message: TOO_MANY_REQUESTS_BODY,
      });
      byWindow.set(windowMs, limiter);
    }

    return limiter(req, res, next);
  };
}

const magicLinkIpCachedLimiter = createFlowLimiter((limits) => limits.magicLink.perIp);
const magicLinkIdentityCachedLimiter = createFlowLimiter(
  (limits) => limits.magicLink.perIdentity,
  getMagicLinkIdentityKey,
);
const otpIpCachedLimiter = createFlowLimiter((limits) => limits.otp.perIp);
const otpIdentityCachedLimiter = createFlowLimiter(
  (limits) => limits.otp.perIdentity,
  getOtpIdentityKey,
);
const oauthIpCachedLimiter = createFlowLimiter((limits) => limits.oauth.perIp);
const oauthProviderCachedLimiter = createFlowLimiter(
  (limits) => limits.oauth.perProvider,
  getOAuthFlowKey,
);

export function dynamicRateLimit(req: Request, res: Response, next: NextFunction) {
  return dynamicLimiter(req, res, next);
}

export function magicLinkIpLimiter(req: Request, res: Response, next: NextFunction) {
  return magicLinkIpCachedLimiter(req, res, next);
}

export function magicLinkEmailLimiter(req: Request, res: Response, next: NextFunction) {
  return magicLinkIdentityCachedLimiter(req, res, next);
}

export function otpIpLimiter(req: Request, res: Response, next: NextFunction) {
  return otpIpCachedLimiter(req, res, next);
}

export function otpIdentityLimiter(req: Request, res: Response, next: NextFunction) {
  return otpIdentityCachedLimiter(req, res, next);
}

export function oauthIpLimiter(req: Request, res: Response, next: NextFunction) {
  return oauthIpCachedLimiter(req, res, next);
}

export function oauthProviderLimiter(req: Request, res: Response, next: NextFunction) {
  return oauthProviderCachedLimiter(req, res, next);
}
