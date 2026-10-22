import { describe, expect, it } from 'vitest';

import {
  assertAuthSecrets,
  authSecret,
  authSecretsRequiredBy,
  MissingAuthSecretError,
  productionSecretMissing,
} from '../../../src/config/authSecrets.js';

const production = { NODE_ENV: 'production', SEAMLESS_SERVICE_TOKEN: 'service-token' };
const provider = { id: 'google' } as never;

describe('authSecret', () => {
  it('returns the configured value', () => {
    expect(authSecret('OAUTH_STATE_SECRET', { ...production, OAUTH_STATE_SECRET: ' s ' })).toBe(
      's',
    );
  });

  it('never falls back to the service token in production', () => {
    expect(() => authSecret('DECOY_SUBJECT_SECRET', production)).toThrow(MissingAuthSecretError);
  });

  it('uses a development-only value outside production', () => {
    expect(authSecret('REFRESH_TOKEN_LOOKUP_SECRET', { APP_ID: 'app', ISSUER: 'http://x' })).toBe(
      'dev-refresh-lookup:app:http://x',
    );
    expect(authSecret('TOTP_SECRET_ENCRYPTION_KEY', {})).toBe('dev-totp-secret:local:local');
    expect(authSecret('OAUTH_STATE_SECRET', {})).toBe('dev-oauth-state:local');
    expect(authSecret('DECOY_SUBJECT_SECRET', {})).toBe('dev-decoy-subject:local');
  });
});

describe('authSecretsRequiredBy', () => {
  it('always needs the refresh lookup and decoy secrets', () => {
    expect(authSecretsRequiredBy({ oauth_providers: [] }, { totpCredentialsExist: false })).toEqual(
      ['REFRESH_TOKEN_LOOKUP_SECRET', 'DECOY_SUBJECT_SECRET'],
    );
  });

  it('needs the TOTP key once a credential exists and the state secret once a provider does', () => {
    expect(
      authSecretsRequiredBy({ oauth_providers: [provider] }, { totpCredentialsExist: true }),
    ).toEqual([
      'REFRESH_TOKEN_LOOKUP_SECRET',
      'DECOY_SUBJECT_SECRET',
      'TOTP_SECRET_ENCRYPTION_KEY',
      'OAUTH_STATE_SECRET',
    ]);
  });
});

describe('productionSecretMissing', () => {
  it('is true only in production without the secret', () => {
    expect(productionSecretMissing('OAUTH_STATE_SECRET', production)).toBe(true);
    expect(
      productionSecretMissing('OAUTH_STATE_SECRET', { ...production, OAUTH_STATE_SECRET: 'c' }),
    ).toBe(false);
    expect(productionSecretMissing('OAUTH_STATE_SECRET', {})).toBe(false);
  });
});

describe('assertAuthSecrets', () => {
  it('passes outside production and when everything needed is set', () => {
    expect(() => assertAuthSecrets({ oauth_providers: [provider] }, true, {})).not.toThrow();
    expect(() =>
      assertAuthSecrets({ oauth_providers: [] }, false, {
        ...production,
        REFRESH_TOKEN_LOOKUP_SECRET: 'a',
        DECOY_SUBJECT_SECRET: 'b',
      }),
    ).not.toThrow();
  });

  it('names every missing secret and how to keep existing data valid', () => {
    expect(() => assertAuthSecrets({ oauth_providers: [provider] }, true, production)).toThrow(
      /REFRESH_TOKEN_LOOKUP_SECRET, DECOY_SUBJECT_SECRET, TOTP_SECRET_ENCRYPTION_KEY, OAUTH_STATE_SECRET are not set[\s\S]*current SEAMLESS_SERVICE_TOKEN value/,
    );
  });

  it('uses the singular for one missing secret', () => {
    expect(() =>
      assertAuthSecrets({ oauth_providers: [] }, false, {
        ...production,
        REFRESH_TOKEN_LOOKUP_SECRET: 'a',
      }),
    ).toThrow('DECOY_SUBJECT_SECRET is not set');
  });
});
