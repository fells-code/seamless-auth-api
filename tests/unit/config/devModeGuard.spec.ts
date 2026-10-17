import { afterEach, describe, expect, it } from 'vitest';

import {
  assertDevModeIsLocal,
  isInsecureDevModeActive,
  isLocalHost,
} from '../../../src/config/devModeGuard.js';

const LOCAL = { ISSUER: 'http://localhost:5312', APP_ORIGINS: 'http://localhost:3000' };

afterEach(() => {
  assertDevModeIsLocal({ NODE_ENV: 'production' });
});

describe('isLocalHost', () => {
  it.each([
    'localhost',
    'auth.localhost',
    'app.test',
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.4',
    '192.168.1.20',
    '[::1]',
    'fd12::1',
    'api',
  ])('treats %s as local', (host) => {
    expect(isLocalHost(host)).toBe(true);
  });

  it.each(['auth.example.com', '203.0.113.7', '172.32.0.1', '8.8.8.8', '2001:db8::1'])(
    'treats %s as reachable from outside',
    (host) => {
      expect(isLocalHost(host)).toBe(false);
    },
  );
});

describe('assertDevModeIsLocal', () => {
  it('does nothing in production, whatever the origins', () => {
    expect(() =>
      assertDevModeIsLocal({ NODE_ENV: 'production', ISSUER: 'https://auth.example.com' }),
    ).not.toThrow();
    expect(isInsecureDevModeActive()).toBe(false);
  });

  it('allows development mode on a local stack', () => {
    expect(() => assertDevModeIsLocal({ NODE_ENV: 'development', ...LOCAL })).not.toThrow();
    expect(isInsecureDevModeActive()).toBe(false);
  });

  it('refuses development mode on a public issuer, naming the setting', () => {
    expect(() =>
      assertDevModeIsLocal({
        NODE_ENV: 'development',
        ISSUER: 'https://auth.example.com',
        APP_ORIGINS: LOCAL.APP_ORIGINS,
      }),
    ).toThrow(/ISSUER=https:\/\/auth\.example\.com/);
  });

  it('refuses development mode when any origin is public', () => {
    expect(() =>
      assertDevModeIsLocal({
        NODE_ENV: 'development',
        ISSUER: LOCAL.ISSUER,
        APP_ORIGINS: 'http://localhost:3000, https://app.example.com',
      }),
    ).toThrow(/APP_ORIGINS=https:\/\/app\.example\.com/);
  });

  // Anything but NODE_ENV=production turns the development behaviour on, so an unset
  // NODE_ENV on a public host is the same risk.
  it('treats an unset NODE_ENV as development mode', () => {
    expect(() => assertDevModeIsLocal({ ISSUER: 'https://auth.example.com' })).toThrow(
      /Refusing to start/,
    );
  });

  it('starts when insecure development mode is allowed on purpose, and reports it', () => {
    expect(() =>
      assertDevModeIsLocal({
        NODE_ENV: 'development',
        ISSUER: 'https://auth.example.com',
        SEAMLESS_ALLOW_INSECURE_DEV: 'true',
      }),
    ).not.toThrow();
    expect(isInsecureDevModeActive()).toBe(true);
  });

  it('ignores entries that are not URLs', () => {
    expect(() =>
      assertDevModeIsLocal({ NODE_ENV: 'development', ...LOCAL, APP_ORIGINS: 'not a url' }),
    ).not.toThrow();
  });
});
