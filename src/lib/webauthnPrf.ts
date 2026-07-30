/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import type { AuthenticationExtensionsClientInputs } from '@simplewebauthn/server';

export const PRF_MIN_SALT_BYTES = 32;

type PrfRequest = {
  salt: string;
  secondSalt?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export function assertValidPrfSalt(salt: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(salt)) {
    throw new Error('PRF salt must be base64url encoded');
  }

  const decoded = Buffer.from(salt, 'base64url');

  if (decoded.length < PRF_MIN_SALT_BYTES) {
    throw new Error(`PRF salt must decode to at least ${PRF_MIN_SALT_BYTES} bytes`);
  }
}

export function buildPrfRegistrationExtensions(
  requestPrf: boolean,
): AuthenticationExtensionsClientInputs | undefined {
  if (!requestPrf) {
    return undefined;
  }

  return {
    prf: {},
  } as unknown as AuthenticationExtensionsClientInputs;
}

export function buildPrfAuthenticationExtensions(
  request?: PrfRequest,
): AuthenticationExtensionsClientInputs | undefined {
  if (!request) {
    return undefined;
  }

  assertValidPrfSalt(request.salt);

  if (request.secondSalt) {
    assertValidPrfSalt(request.secondSalt);
  }

  return {
    prf: {
      eval: {
        first: request.salt,
        ...(request.secondSalt ? { second: request.secondSalt } : {}),
      },
    },
  } as unknown as AuthenticationExtensionsClientInputs;
}

export function getRegistrationPrfCapable(attestationResponse: unknown) {
  if (!isRecord(attestationResponse)) {
    return false;
  }

  const extensionResults = attestationResponse.clientExtensionResults;

  if (!isRecord(extensionResults)) {
    return false;
  }

  const prf = extensionResults.prf;

  if (!isRecord(prf)) {
    return false;
  }

  return prf.enabled === true;
}

export function containsPrfOutput(credentialResponse: unknown) {
  if (!isRecord(credentialResponse)) {
    return false;
  }

  const extensionResults = credentialResponse.clientExtensionResults;

  if (!isRecord(extensionResults)) {
    return false;
  }

  const prf = extensionResults.prf;

  if (!isRecord(prf)) {
    return false;
  }

  return isRecord(prf.results);
}
