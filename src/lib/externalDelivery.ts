/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';

import { validateInternalServiceToken } from '../middleware/authenticateServiceToken.js';

const EXTERNAL_DELIVERY_HEADER = 'x-seamless-auth-delivery-mode';
const SERVICE_TOKEN_HEADER = 'x-seamless-service-token';
const INCLUDE_SENSITIVE_HEADER = 'x-seamless-auth-include-sensitive';

function extractBearerToken(headerValue: string | undefined): string | null {
  if (!headerValue) {
    return null;
  }

  if (headerValue.startsWith('Bearer ')) {
    return headerValue.slice('Bearer '.length).trim() || null;
  }

  return headerValue.trim() || null;
}

export function wantsExternalDelivery(req: Request) {
  return req.get(EXTERNAL_DELIVERY_HEADER)?.toLowerCase() === 'external';
}

export async function canReturnExternalDelivery(req: Request) {
  if (!wantsExternalDelivery(req)) {
    return false;
  }

  if (process.env.NODE_ENV !== 'production') {
    return true;
  }

  const serviceToken = extractBearerToken(req.get(SERVICE_TOKEN_HEADER) ?? undefined);

  if (!serviceToken) {
    return false;
  }

  const decoded = await validateInternalServiceToken(serviceToken);

  return Boolean(
    decoded?.sub && decoded.iss === 'seamless-portal-api' && decoded.aud === 'seamless-auth',
  );
}

export function canReturnSensitiveDevelopmentDetails(req: Request) {
  if (process.env.NODE_ENV === 'production') {
    return false;
  }

  return req.get(INCLUDE_SENSITIVE_HEADER)?.toLowerCase() === 'true';
}
