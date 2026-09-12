/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { isIP } from 'node:net';

import { NextFunction, Request, Response } from 'express';

import { validateInternalServiceToken } from './authenticateServiceToken.js';

const CLIENT_IP_HEADER = 'x-seamless-client-ip';
const CLIENT_USER_AGENT_HEADER = 'x-seamless-client-user-agent';
const SERVICE_TOKEN_HEADER = 'x-seamless-service-token';

// Bounds the audit row. Real user agents run to a few hundred characters.
const MAX_USER_AGENT_LENGTH = 512;

function extractTrustedClientIp(headerValue: string | undefined): string | null {
  if (!headerValue) {
    return null;
  }

  const candidate = headerValue
    .split(',')
    .map((part) => part.trim())
    .find((part) => part.length > 0);

  if (!candidate || isIP(candidate) === 0) {
    return null;
  }

  return candidate;
}

function extractTrustedUserAgent(headerValue: string | undefined): string | null {
  const candidate = headerValue?.trim().slice(0, MAX_USER_AGENT_LENGTH);

  return candidate || null;
}

function extractServiceToken(headerValue: string | undefined): string | null {
  if (!headerValue) {
    return null;
  }

  if (headerValue.startsWith('Bearer ')) {
    return headerValue.slice('Bearer '.length).trim() || null;
  }

  return headerValue.trim() || null;
}

/**
 * Lets a trusted server adapter say who it is calling on behalf of.
 *
 * The adapter is the only client this API sees, so without these headers every audit
 * row, session and rate limit key would carry the adapter's own address and user
 * agent. Both are honoured only alongside a valid internal service token, since either
 * would otherwise let any caller choose its audit identity.
 *
 * The user agent replaces the request header in place, so everything downstream that
 * reads it (audit rows, the session record, the magic link device binding) sees the
 * browser's without knowing the substitution happened.
 */
export async function applyTrustedClientContext(req: Request, _res: Response, next: NextFunction) {
  const trustedClientIp = extractTrustedClientIp(req.get(CLIENT_IP_HEADER) ?? undefined);
  const trustedUserAgent = extractTrustedUserAgent(req.get(CLIENT_USER_AGENT_HEADER) ?? undefined);

  if (!trustedClientIp && !trustedUserAgent) {
    next();
    return;
  }

  const serviceToken = extractServiceToken(req.get(SERVICE_TOKEN_HEADER) ?? undefined);

  if (!serviceToken) {
    next();
    return;
  }

  const decoded = await validateInternalServiceToken(serviceToken);

  if (!decoded?.sub || decoded.iss !== 'seamless-portal-api' || decoded.aud !== 'seamless-auth') {
    next();
    return;
  }

  if (trustedClientIp) {
    Object.defineProperty(req, 'ip', {
      configurable: true,
      enumerable: true,
      value: trustedClientIp,
      writable: false,
    });

    Object.defineProperty(req, 'ips', {
      configurable: true,
      enumerable: true,
      value: [trustedClientIp],
      writable: false,
    });

    (req as Request & { trustedClientIp?: string }).trustedClientIp = trustedClientIp;
  }

  if (trustedUserAgent) {
    req.headers['user-agent'] = trustedUserAgent;
  }

  next();
}
