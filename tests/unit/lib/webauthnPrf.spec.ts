import { describe, expect, it } from 'vitest';

import {
  assertValidPrfSalt,
  buildPrfAuthenticationExtensions,
  buildPrfRegistrationExtensions,
  containsPrfOutput,
  extractPasskeyPrfResult,
  getRegistrationPrfCapable,
} from '../../../src/lib/webauthnPrf.js';

function salt(byte = 1) {
  return Buffer.alloc(32, byte).toString('base64url');
}

describe('webauthnPrf', () => {
  it('builds no extension for normal registration', () => {
    expect(buildPrfRegistrationExtensions(false)).toBeUndefined();
  });

  it('builds PRF registration extension when requested', () => {
    expect(buildPrfRegistrationExtensions(true)).toEqual({ prf: {} });
  });

  it('builds PRF assertion extension with base64url salts', () => {
    expect(buildPrfAuthenticationExtensions({ salt: salt(), secondSalt: salt(2) })).toEqual({
      prf: {
        eval: {
          first: salt(),
          second: salt(2),
        },
      },
    });
  });

  it('rejects salts that are not base64url or are too short', () => {
    expect(() => assertValidPrfSalt('not valid!')).toThrow('base64url');
    expect(() => assertValidPrfSalt(Buffer.alloc(16).toString('base64url'))).toThrow(
      'at least 32 bytes',
    );
  });

  it('detects PRF capability and forbidden PRF output in client extension results', () => {
    expect(
      getRegistrationPrfCapable({
        clientExtensionResults: { prf: { enabled: true } },
      }),
    ).toBe(true);

    expect(
      containsPrfOutput({
        clientExtensionResults: { prf: { results: { first: 'secret-output' } } },
      }),
    ).toBe(true);
  });

  it('extracts browser PRF output without needing to send it to the API', () => {
    const output = Uint8Array.from([1, 2, 3, 4]);
    const result = extractPasskeyPrfResult({
      id: 'cred-1',
      getClientExtensionResults: () => ({
        prf: {
          results: {
            first: output.buffer,
          },
        },
      }),
    });

    expect(result?.credentialId).toBe('cred-1');
    expect(Array.from(result?.output ?? [])).toEqual([1, 2, 3, 4]);
    expect(result?.outputBase64url).toBe('AQIDBA');
  });
});
