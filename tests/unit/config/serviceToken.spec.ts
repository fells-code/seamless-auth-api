import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  assertServiceTokenConfig,
  getOidcServiceToken,
  getServiceToken,
  OidcServiceTokenReuseError,
  resolveServiceToken,
  ServiceTokenConflictError,
} from '../../../src/config/serviceToken.js';
import getLogger from '../../../src/utils/logger.js';

describe('service token resolution', () => {
  beforeEach(() => {
    vi.stubEnv('SEAMLESS_SERVICE_TOKEN', '');
    vi.stubEnv('API_SERVICE_TOKEN', '');
  });

  it('reads SEAMLESS_SERVICE_TOKEN when only the new name is set', () => {
    vi.stubEnv('SEAMLESS_SERVICE_TOKEN', 'new-token');

    expect(resolveServiceToken()).toEqual({
      value: 'new-token',
      source: 'SEAMLESS_SERVICE_TOKEN',
    });
    expect(getServiceToken()).toBe('new-token');
  });

  it('falls back to API_SERVICE_TOKEN when only the old name is set', () => {
    vi.stubEnv('API_SERVICE_TOKEN', 'old-token');

    expect(resolveServiceToken()).toEqual({ value: 'old-token', source: 'API_SERVICE_TOKEN' });
    expect(getServiceToken()).toBe('old-token');
  });

  it('accepts both names when they hold the same value', () => {
    vi.stubEnv('SEAMLESS_SERVICE_TOKEN', 'same-token');
    vi.stubEnv('API_SERVICE_TOKEN', ' same-token ');

    expect(resolveServiceToken()).toEqual({
      value: 'same-token',
      source: 'SEAMLESS_SERVICE_TOKEN',
    });
  });

  it('throws naming both variables when they hold different values', () => {
    vi.stubEnv('SEAMLESS_SERVICE_TOKEN', 'new-token');
    vi.stubEnv('API_SERVICE_TOKEN', 'old-token');

    expect(() => resolveServiceToken()).toThrow(ServiceTokenConflictError);
    expect(() => getServiceToken()).toThrow(
      /SEAMLESS_SERVICE_TOKEN and API_SERVICE_TOKEN are both set to different values/,
    );
  });

  it('treats blank values as unset', () => {
    vi.stubEnv('SEAMLESS_SERVICE_TOKEN', '   ');

    expect(resolveServiceToken()).toEqual({ value: undefined, source: null });
    expect(getServiceToken()).toBeUndefined();
  });

  it('reads from an explicit env object', () => {
    expect(getServiceToken({ SEAMLESS_SERVICE_TOKEN: 'explicit' })).toBe('explicit');
  });
});

describe('assertServiceTokenConfig', () => {
  const logger = getLogger('serviceToken');

  beforeEach(() => {
    vi.spyOn(logger, 'info');
    vi.spyOn(logger, 'warn');
  });

  it('logs a single info notice when only API_SERVICE_TOKEN is set', () => {
    const resolved = assertServiceTokenConfig({ API_SERVICE_TOKEN: 'old-token' });

    expect(resolved).toEqual({ value: 'old-token', source: 'API_SERVICE_TOKEN' });
    expect(logger.info).toHaveBeenCalledTimes(1);
    expect(logger.info).toHaveBeenCalledWith(
      expect.stringContaining('SEAMLESS_SERVICE_TOKEN is the preferred name'),
    );
  });

  it('stays quiet when SEAMLESS_SERVICE_TOKEN is set', () => {
    assertServiceTokenConfig({ SEAMLESS_SERVICE_TOKEN: 'new-token' });
    assertServiceTokenConfig({ SEAMLESS_SERVICE_TOKEN: 'same', API_SERVICE_TOKEN: 'same' });

    expect(logger.info).not.toHaveBeenCalled();
  });

  it('stays quiet when neither name is set', () => {
    expect(assertServiceTokenConfig({})).toEqual({ value: undefined, source: null });
    expect(logger.info).not.toHaveBeenCalled();
  });

  it('fails fast when the two names disagree', () => {
    expect(() =>
      assertServiceTokenConfig({ SEAMLESS_SERVICE_TOKEN: 'a', API_SERVICE_TOKEN: 'b' }),
    ).toThrow(
      'SEAMLESS_SERVICE_TOKEN and API_SERVICE_TOKEN are both set to different values. Set only SEAMLESS_SERVICE_TOKEN, or set both to the same value.',
    );
  });

  it('accepts a provider service token distinct from the adapter one', () => {
    expect(() =>
      assertServiceTokenConfig({
        SEAMLESS_SERVICE_TOKEN: 'adapter',
        SEAMLESS_OIDC_SERVICE_TOKEN: 'edge',
      }),
    ).not.toThrow();
  });

  it('refuses a provider service token equal to either adapter name', () => {
    expect(() =>
      assertServiceTokenConfig({
        SEAMLESS_SERVICE_TOKEN: 'same',
        SEAMLESS_OIDC_SERVICE_TOKEN: 'same',
      }),
    ).toThrow(OidcServiceTokenReuseError);
    expect(() =>
      assertServiceTokenConfig({ API_SERVICE_TOKEN: 'same', SEAMLESS_OIDC_SERVICE_TOKEN: 'same' }),
    ).toThrow(OidcServiceTokenReuseError);
  });
});

describe('getOidcServiceToken', () => {
  it('reads the provider service token and treats blank as unset', () => {
    expect(getOidcServiceToken({ SEAMLESS_OIDC_SERVICE_TOKEN: ' edge ' })).toBe('edge');
    expect(getOidcServiceToken({ SEAMLESS_OIDC_SERVICE_TOKEN: ' ' })).toBeUndefined();
    vi.stubEnv('SEAMLESS_OIDC_SERVICE_TOKEN', 'from-env');
    expect(getOidcServiceToken()).toBe('from-env');
  });
});
