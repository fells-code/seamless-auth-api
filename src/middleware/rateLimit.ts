/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

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

const magicLinkIpCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
});

const magicLinkIdentityCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyGenerator: getMagicLinkIdentityKey,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
});

const otpIpCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
});

const otpIdentityCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  keyGenerator: getOtpIdentityKey,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
});

const oauthIpCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
});

const oauthProviderCachedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  keyGenerator: getOAuthFlowKey,
  standardHeaders: true,
  legacyHeaders: false,
  skip: rateLimitsDisabled,
  message: TOO_MANY_REQUESTS_BODY,
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
