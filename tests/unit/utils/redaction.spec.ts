import { describe, expect, it } from 'vitest';

import {
  REDACTED,
  redactMetadata,
  redactSensitiveText,
  redactSensitiveValue,
} from '../../../src/utils/redaction.js';

describe('redaction utilities', () => {
  it('redacts sensitive keys while preserving operational metadata', () => {
    expect(
      redactMetadata({
        providerId: 'google',
        email: 'user@example.com',
        phone: '+15555550123',
        accessToken: 'access-token',
        refresh_token: 'refresh-token',
        totpSecret: 'totp-secret',
        prf: {
          salt: 'salt-value',
          results: {
            first: 'local-key-material',
          },
        },
        oauth: {
          clientSecret: 'secret-value',
          clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
        },
        scopes: ['admin:read'],
      }),
    ).toEqual({
      providerId: 'google',
      email: REDACTED,
      phone: REDACTED,
      accessToken: REDACTED,
      refresh_token: REDACTED,
      totpSecret: REDACTED,
      prf: REDACTED,
      oauth: {
        clientSecret: REDACTED,
        clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
      },
      scopes: ['admin:read'],
    });
  });

  it('redacts token, salt, code, and email values embedded in text', () => {
    expect(
      redactSensitiveText(
        'Bearer abc.def.ghi /magic-link/verify/magic-token token=magic-token code=oauth-code salt=prf-salt user@example.com',
      ),
    ).toBe(
      'Bearer [REDACTED] /magic-link/verify/[REDACTED] token=[REDACTED] code=[REDACTED] salt=[REDACTED] [REDACTED]',
    );
  });

  it('redacts phone and labeled identifier values embedded in text', () => {
    expect(
      redactSensitiveText(
        'phone number: +15555550123 email address: user@example.com identifier: +15555550124',
      ),
    ).toBe('phone number: [REDACTED] email address: [REDACTED] identifier: [REDACTED]');
  });

  it('redacts otp and verificationToken query parameters in a URL', () => {
    expect(
      redactSensitiveText('Received GET request for /verify?otp=999888&verificationToken=abc123'),
    ).toBe('Received GET request for /verify?otp=[REDACTED]&verificationToken=[REDACTED]');
  });

  it('returns null and undefined metadata unchanged', () => {
    expect(redactMetadata(null)).toBeNull();
    expect(redactMetadata(undefined)).toBeUndefined();
  });

  describe('redactSensitiveValue', () => {
    it('returns null and undefined unchanged', () => {
      expect(redactSensitiveValue(null)).toBeNull();
      expect(redactSensitiveValue(undefined)).toBeUndefined();
    });

    it('returns non-string primitives unchanged', () => {
      expect(redactSensitiveValue(42)).toBe(42);
      expect(redactSensitiveValue(true)).toBe(true);
    });

    it('serializes Date values to ISO strings', () => {
      expect(redactSensitiveValue(new Date('2026-01-01T00:00:00.000Z'))).toBe(
        '2026-01-01T00:00:00.000Z',
      );
    });

    it('stops recursing once the max depth limit is reached', () => {
      let nested: unknown = 'leaf';
      for (let i = 0; i < 9; i += 1) {
        nested = { child: nested };
      }

      let cursor = redactSensitiveValue(nested) as Record<string, unknown>;
      for (let i = 0; i < 8; i += 1) {
        cursor = cursor.child as Record<string, unknown>;
      }

      expect(cursor).toBe('[REDACTED_DEPTH_LIMIT]');
    });
  });
});
