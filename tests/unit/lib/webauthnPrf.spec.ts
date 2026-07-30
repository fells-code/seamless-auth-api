import { describe, expect, it } from 'vitest';

import {
  assertValidPrfSalt,
  buildPrfAuthenticationExtensions,
  buildPrfRegistrationExtensions,
  containsPrfOutput,
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

  it('builds no assertion extension when no PRF request is provided', () => {
    expect(buildPrfAuthenticationExtensions(undefined)).toBeUndefined();
  });

  it('omits the second salt from the assertion extension when not requested', () => {
    expect(buildPrfAuthenticationExtensions({ salt: salt() })).toEqual({
      prf: {
        eval: {
          first: salt(),
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

  it('reports no PRF capability when the shape is missing or malformed', () => {
    expect(getRegistrationPrfCapable(null)).toBe(false);
    expect(getRegistrationPrfCapable({ clientExtensionResults: 'nope' })).toBe(false);
    expect(getRegistrationPrfCapable({ clientExtensionResults: { prf: 'nope' } })).toBe(false);
    expect(getRegistrationPrfCapable({ clientExtensionResults: { prf: { enabled: false } } })).toBe(
      false,
    );
  });

  it('reports no PRF output when the shape is missing or malformed', () => {
    expect(containsPrfOutput(null)).toBe(false);
    expect(containsPrfOutput({ clientExtensionResults: 'nope' })).toBe(false);
    expect(containsPrfOutput({ clientExtensionResults: { prf: 'nope' } })).toBe(false);
    expect(containsPrfOutput({ clientExtensionResults: { prf: {} } })).toBe(false);
  });
});
