import { describe, expect, it } from 'vitest';

import {
  base32Decode,
  base32Encode,
  buildTotpUri,
  generateTotpCode,
  verifyTotpCode,
} from '../../../src/utils/totp.js';

describe('totp utils', () => {
  it('round-trips base32 encoding', () => {
    const value = Buffer.from('hello world');

    expect(base32Decode(base32Encode(value)).toString('utf8')).toBe('hello world');
  });

  it('generates RFC 6238 compatible codes', () => {
    const secret = base32Encode(Buffer.from('12345678901234567890'));

    expect(generateTotpCode({ secret, counter: 1, digits: 8 })).toBe('94287082');
  });

  it('verifies codes within the allowed window and rejects replayed counters', () => {
    const secret = base32Encode(Buffer.from('12345678901234567890'));
    const timestamp = 59_000;
    const code = generateTotpCode({ secret, counter: 1, digits: 8 });

    expect(
      verifyTotpCode({
        secret,
        code,
        timestamp,
        digits: 8,
        window: 0,
      }),
    ).toEqual({ verified: true, counter: 1 });

    expect(
      verifyTotpCode({
        secret,
        code,
        timestamp,
        digits: 8,
        window: 0,
        lastUsedCounter: 1,
      }),
    ).toEqual({ verified: false, counter: null });
  });

  it('builds an otpauth URI for authenticator apps', () => {
    const uri = buildTotpUri({
      issuer: 'Seamless Auth',
      accountName: 'test@example.com',
      secret: 'ABC123',
    });

    expect(uri).toContain('otpauth://totp/Seamless%20Auth:test%40example.com');
    expect(uri).toContain('secret=ABC123');
    expect(uri).toContain('issuer=Seamless+Auth');
  });
});
