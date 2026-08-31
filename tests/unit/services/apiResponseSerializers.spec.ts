import { describe, expect, it } from 'vitest';

import {
  serializeApiUser,
  serializeCredential,
  serializeSession,
} from '../../../src/services/apiResponseSerializers';

describe('api response serializers', () => {
  it('minimizes user responses to non-secret account fields', () => {
    const user = serializeApiUser({
      id: 'user-1',
      email: 'test@example.com',
      phone: '+14155552671',
      roles: ['admin:read'],
      revoked: false,
      emailVerified: true,
      phoneVerified: true,
      emailVerificationToken: 'email-token',
      phoneVerificationToken: 'phone-token',
    });

    expect(user).toEqual(
      expect.objectContaining({
        id: 'user-1',
        email: 'test@example.com',
        phone: '+14155552671',
        roles: ['admin:read'],
      }),
    );
    expect(user).not.toHaveProperty('emailVerificationToken');
    expect(user).not.toHaveProperty('phoneVerificationToken');
  });

  it('preserves null phone values in user responses', () => {
    const user = serializeApiUser({
      id: 'user-1',
      email: 'test@example.com',
      phone: null,
      roles: ['user'],
    });

    expect(user).toEqual(
      expect.objectContaining({
        id: 'user-1',
        email: 'test@example.com',
        phone: null,
      }),
    );
  });

  it('minimizes credential responses without public key material', () => {
    const credential = serializeCredential({
      id: 'credential-1',
      userId: 'user-1',
      publicKey: 'public-key',
      counter: 10,
      backedup: true,
      prfCapable: true,
      friendlyName: 'Laptop',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
    });

    expect(credential).toEqual(
      expect.objectContaining({
        id: 'credential-1',
        counter: 10,
        backedup: true,
        backedUp: true,
        prfCapable: true,
      }),
    );
    expect(credential).not.toHaveProperty('userId');
    expect(credential).not.toHaveProperty('publicKey');
  });

  it('minimizes session responses without refresh token internals', () => {
    const session = serializeSession(
      {
        id: 'session-1',
        refreshTokenHash: 'hash',
        refreshTokenLookup: 'lookup',
        idleExpiresAt: new Date('2026-01-01T00:10:00.000Z'),
        lastUsedAt: new Date('2026-01-01T00:00:00.000Z'),
        expiresAt: new Date('2026-01-02T00:00:00.000Z'),
      },
      'session-1',
    );

    expect(session).toEqual(
      expect.objectContaining({
        id: 'session-1',
        lastUsedAt: '2026-01-01T00:00:00.000Z',
        expiresAt: '2026-01-02T00:00:00.000Z',
        current: true,
      }),
    );
    expect(session).not.toHaveProperty('refreshTokenHash');
    expect(session).not.toHaveProperty('refreshTokenLookup');
    expect(session).not.toHaveProperty('idleExpiresAt');
  });

  it('reads fields from Sequelize-style get({ plain: true }) instances', () => {
    const model = {
      get: ({ plain }: { plain: boolean }) =>
        plain ? { id: 'model-1', email: 'm@example.com', roles: ['user'] } : undefined,
    };

    expect(serializeApiUser(model)).toEqual(
      expect.objectContaining({
        id: 'model-1',
        email: 'm@example.com',
        phone: null,
        roles: ['user'],
      }),
    );
  });

  it('ignores get() results that are not plain records', () => {
    const model = { get: () => 'not-a-record' };

    expect(serializeApiUser(model)).toEqual(expect.objectContaining({ id: '', email: '' }));
  });

  it('coerces non-string scalar user fields', () => {
    const user = serializeApiUser({ id: 123, email: 'a@example.com', phone: 4155551234 });

    expect(user.id).toBe('123');
    expect(user.phone).toBe('4155551234');
  });

  it('returns undefined for non-record sources', () => {
    const user = serializeApiUser('not-an-object' as unknown);

    expect(user).toEqual({ id: '', email: '', phone: null, roles: [] });
  });

  it('parses numeric strings and falls back for non-numeric counters', () => {
    expect(serializeCredential({ counter: '42' }).counter).toBe(42);
    expect(serializeCredential({ counter: 'not-a-number' }).counter).toBe(0);
    expect(serializeCredential({ counter: Number.NaN }).counter).toBe(0);
  });

  it('normalizes assorted date field shapes', () => {
    const numericDate = serializeCredential({
      lastUsedAt: null,
      createdAt: Date.parse('2026-03-01T00:00:00.000Z'),
    });
    expect(numericDate.lastUsedAt).toBeNull();
    expect(numericDate.createdAt).toBe('2026-03-01T00:00:00.000Z');

    const stringDate = serializeCredential({ createdAt: '2026-03-02T00:00:00.000Z' });
    expect(stringDate.createdAt).toBe('2026-03-02T00:00:00.000Z');

    const invalidNumber = serializeCredential({ createdAt: Number.NaN });
    expect(invalidNumber).not.toHaveProperty('createdAt');

    const invalidType = serializeCredential({ createdAt: true });
    expect(invalidType).not.toHaveProperty('createdAt');
  });

  it('preserves hybrid and other post-2019 transports', () => {
    const credential = serializeCredential({
      id: 'credential-hybrid',
      // A cross-device passkey (phone authenticating a desktop browser).
      transports: ['hybrid', 'cable', 'smart-card'],
    });

    expect(credential.transports).toEqual(['hybrid', 'cable', 'smart-card']);
  });

  it('filters webauthn transports and device type to known values', () => {
    const credential = serializeCredential({
      id: 'credential-2',
      transports: ['usb', 'ble', 'bogus', 'nfc', 'internal'],
      deviceType: 'multiDevice',
    });

    expect(credential.transports).toEqual(['usb', 'ble', 'nfc', 'internal']);
    expect(credential.deviceType).toBe('multiDevice');
  });

  it('coerces a non-array transports value to an empty list', () => {
    const credential = serializeCredential({ id: 'credential-3', transports: 'usb' });

    expect(credential.transports).toEqual([]);
  });

  it('omits transports and device type when absent or unknown', () => {
    const credential = serializeCredential({ id: 'credential-4', deviceType: 'unknown' });

    expect(credential).not.toHaveProperty('transports');
    expect(credential).not.toHaveProperty('deviceType');
  });

  it('marks sessions as not current when no current session id is provided', () => {
    const session = serializeSession({ id: 'session-2' });

    expect(session.current).toBe(false);
  });
});
