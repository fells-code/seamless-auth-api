/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { isIP } from 'node:net';

import { NextFunction, Request, Response } from 'express';

import { validateInternalServiceToken } from './authenticateServiceToken.js';

const CLIENT_IP_HEADER = 'x-seamless-client-ip';
const SERVICE_TOKEN_HEADER = 'x-seamless-service-token';

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

function extractServiceToken(headerValue: string | undefined): string | null {
  if (!headerValue) {
    return null;
  }

  if (headerValue.startsWith('Bearer ')) {
    return headerValue.slice('Bearer '.length).trim() || null;
  }

  return headerValue.trim() || null;
}

export async function applyTrustedClientIp(req: Request, _res: Response, next: NextFunction) {
  const trustedClientIp = extractTrustedClientIp(req.get(CLIENT_IP_HEADER) ?? undefined);

  if (!trustedClientIp) {
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

  next();
}
