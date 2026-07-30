/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import jwt, { JwtPayload } from 'jsonwebtoken';

import getLogger from '../utils/logger.js';
import { getSecret } from '../utils/secretsStore.js';

const logger = getLogger('authenticateServiceToken');

let cachedSecret: string | null = null;
const INTERNAL_SERVICE_TOKEN_ALGORITHMS = ['HS256', 'HS384', 'HS512'] as const;

interface InternalServiceTokenValidationOptions {
  logInvalid?: boolean;
}

function getJwtAlgorithm(token: string): string | null {
  const decoded = jwt.decode(token, { complete: true });

  if (!decoded || typeof decoded !== 'object') {
    return null;
  }

  const alg = (decoded as { header?: { alg?: unknown } }).header?.alg;

  return typeof alg === 'string' ? alg : null;
}

function usesSupportedInternalServiceAlgorithm(token: string) {
  const alg = getJwtAlgorithm(token);

  if (!alg) {
    return true;
  }

  return (INTERNAL_SERVICE_TOKEN_ALGORITHMS as readonly string[]).includes(alg);
}

async function getInternalSecret() {
  if (cachedSecret) return cachedSecret;
  cachedSecret = await getSecret('API_SERVICE_TOKEN');
  return cachedSecret;
}

export async function validateInternalServiceToken(
  token: string,
  options: InternalServiceTokenValidationOptions = {},
): Promise<JwtPayload | null> {
  const internalSecret = await getInternalSecret();

  if (!token || !internalSecret) {
    return null;
  }

  try {
    if (!usesSupportedInternalServiceAlgorithm(token)) {
      if (options.logInvalid) {
        logger.warn('Rejected internal service token with unsupported algorithm');
      }

      return null;
    }

    return jwt.verify(token, internalSecret, {
      algorithms: [...INTERNAL_SERVICE_TOKEN_ALGORITHMS],
    }) as JwtPayload;
  } catch (error: unknown) {
    if (options.logInvalid) {
      logger.error(`An error occured validating api to api service. ${error}`);
    }

    return null;
  }
}
