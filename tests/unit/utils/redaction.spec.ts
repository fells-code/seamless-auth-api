import { describe, expect, it } from 'vitest';

import {
  escapeLogControlCharacters,
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

  // #158 requires the recovery proofing record to be readable in the audit trail.
  // Redaction strips identifiers from metadata, so the field names and the shape of
  // an evidence reference have to survive it or the record is worthless.
  describe('recovery proofing metadata', () => {
    it('keeps a proofing record intact', () => {
      const metadata = {
        targetUser: 'user-1',
        actingAdmin: 'admin-9',
        proofing: {
          method: 'remote_exception',
          evidenceRef: 'TICKET-1042',
          approver: 'j.reyes',
        },
      };

      expect(redactMetadata(metadata)).toEqual(metadata);
    });

    it('still redacts personal data if an operator puts it in the evidence reference', () => {
      const redacted = redactMetadata({
        proofing: { method: 'in_person', evidenceRef: 'checked id for jane@example.gov' },
      }) as { proofing: { evidenceRef: string } };

      expect(redacted.proofing.evidenceRef).not.toContain('jane@example.gov');
    });
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

  describe('untrusted keys', () => {
    it('redacts a __proto__ key as data instead of losing it to the setter', () => {
      const redacted = redactMetadata(
        JSON.parse('{"__proto__": {"isAdmin": true}, "providerId": "google"}'),
      ) as Record<string, unknown>;

      expect(Object.keys(redacted)).toContain('__proto__');
      expect(Object.getOwnPropertyDescriptor(redacted, '__proto__')?.value).toEqual({
        isAdmin: true,
      });
      expect(redacted.providerId).toBe('google');
    });

    it('leaves the prototype of an ordinary object alone', () => {
      const redacted = redactMetadata(JSON.parse('{"__proto__": {"isAdmin": true}}')) as Record<
        string,
        unknown
      >;

      expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
      expect(Object.getPrototypeOf(redacted)).toBeNull();
    });

    it('records the key rather than dropping it, and reparses inert', () => {
      const redacted = redactMetadata(JSON.parse('{"__proto__": {"a": 1}, "b": 2}'));
      const roundTripped = JSON.parse(JSON.stringify(redacted));

      // Preserved as data: an audit trail that silently drops a key the caller sent
      // is worse than one that records it.
      expect(Object.getOwnPropertyDescriptor(roundTripped, '__proto__')?.value).toEqual({ a: 1 });
      expect(roundTripped.b).toBe(2);
      expect(({} as Record<string, unknown>).a).toBeUndefined();
    });
  });

  describe('escapeLogControlCharacters', () => {
    it('keeps a forged entry on one line', () => {
      expect(escapeLogControlCharacters('GET /a\nINFO - forged entry')).toBe(
        'GET /a\\nINFO - forged entry',
      );
    });

    it('escapes carriage returns and tabs', () => {
      expect(escapeLogControlCharacters('a\rb\tc')).toBe('a\\rb\\tc');
    });

    it('escapes other control characters by code point', () => {
      expect(escapeLogControlCharacters('a\u0000b\u007f')).toBe('a\\x00b\\x7f');
    });

    it('leaves ordinary text untouched', () => {
      expect(escapeLogControlCharacters('GET /users/me 200')).toBe('GET /users/me 200');
    });
  });
});
