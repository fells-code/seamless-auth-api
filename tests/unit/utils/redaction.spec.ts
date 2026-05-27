import { describe, expect, it } from 'vitest';

import { REDACTED, redactMetadata, redactSensitiveText } from '../../../src/utils/redaction.js';

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
});
