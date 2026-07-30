/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';

import { validateInternalServiceToken } from '../middleware/authenticateServiceToken.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('externalDelivery');

const EXTERNAL_DELIVERY_HEADER = 'x-seamless-auth-delivery-mode';
const SERVICE_TOKEN_HEADER = 'x-seamless-service-token';
const UNCREDENTIALED_OPT_IN = 'ALLOW_UNCREDENTIALED_DELIVERY_SECRETS';

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

/**
 * Opt-in escape hatch for local development, where returning delivery secrets in the
 * response body replaces a real mail/SMS provider. It must be set deliberately, and it is
 * refused outright under a production NODE_ENV so it can never become the deployed default.
 */
function uncredentialedSecretsAllowed() {
  if (process.env[UNCREDENTIALED_OPT_IN] !== 'true') {
    return false;
  }

  if (process.env.NODE_ENV === 'production') {
    logger.error(`${UNCREDENTIALED_OPT_IN} is set in a production environment and was ignored.`);
    return false;
  }

  return true;
}

export async function canReturnExternalDelivery(req: Request) {
  if (!wantsExternalDelivery(req)) {
    return false;
  }

  if (uncredentialedSecretsAllowed()) {
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
