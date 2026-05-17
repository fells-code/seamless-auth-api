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

type PrfCredentialResult = {
  id: string;
  getClientExtensionResults: () => {
    prf?: {
      results?: {
        first?: ArrayBuffer | ArrayBufferView;
        second?: ArrayBuffer | ArrayBufferView;
      };
    };
  };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function toBase64Url(bytes: Uint8Array) {
  return Buffer.from(bytes).toString('base64url');
}

function toUint8Array(value: ArrayBuffer | ArrayBufferView) {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
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

export function extractPasskeyPrfResult(credential: PrfCredentialResult) {
  const first = credential.getClientExtensionResults().prf?.results?.first;

  if (!first) {
    return null;
  }

  const output = toUint8Array(first);

  return {
    credentialId: credential.id,
    output,
    outputBase64url: toBase64Url(output),
  };
}
