import { describe, expect, it } from 'vitest';

import {
  WebAuthnAssertionStartSchema,
  WebAuthnPrfRequestSchema,
  WebAuthnRegisterStartQuerySchema,
} from '../../../src/schemas/webauthn.requests.js';

const validSalt = Buffer.alloc(32).toString('base64url');
const shortSalt = Buffer.alloc(10).toString('base64url');

describe('WebAuthnPrfRequestSchema', () => {
  it('accepts a valid base64url salt', () => {
    const parsed = WebAuthnPrfRequestSchema.safeParse({ salt: validSalt });

    expect(parsed.success).toBe(true);
  });

  it('accepts a valid salt and second salt', () => {
    const parsed = WebAuthnPrfRequestSchema.safeParse({
      salt: validSalt,
      secondSalt: validSalt,
    });

    expect(parsed.success).toBe(true);
  });

  it('rejects a salt that decodes to too few bytes', () => {
    const parsed = WebAuthnPrfRequestSchema.safeParse({ salt: shortSalt });

    expect(parsed.success).toBe(false);
    expect(
      parsed.success === false &&
        parsed.error.issues.some((i) => i.message.includes('at least 32 bytes')),
    ).toBe(true);
  });

  it('rejects a non-base64url salt', () => {
    const parsed = WebAuthnPrfRequestSchema.safeParse({ salt: 'not valid!!' });

    expect(parsed.success).toBe(false);
    expect(
      parsed.success === false &&
        parsed.error.issues.some((i) => i.message === 'PRF salt must be base64url encoded'),
    ).toBe(true);
  });

  it('rejects a valid salt with an invalid second salt', () => {
    const parsed = WebAuthnPrfRequestSchema.safeParse({
      salt: validSalt,
      secondSalt: shortSalt,
    });

    expect(parsed.success).toBe(false);
  });
});

describe('WebAuthnRegisterStartQuerySchema', () => {
  it('coerces the "true" and "false" strings into booleans', () => {
    const parsed = WebAuthnRegisterStartQuerySchema.safeParse({
      requestPrf: 'true',
      requirePrf: 'false',
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.requestPrf).toBe(true);
      expect(parsed.data.requirePrf).toBe(false);
    }
  });

  it('leaves unrelated values untouched so validation rejects them', () => {
    const parsed = WebAuthnRegisterStartQuerySchema.safeParse({ requestPrf: 'maybe' });

    expect(parsed.success).toBe(false);
  });
});

describe('WebAuthnAssertionStartSchema', () => {
  it('defaults to an empty object when no value is supplied', () => {
    const parsed = WebAuthnAssertionStartSchema.safeParse(undefined);

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data).toEqual({});
    }
  });
});
