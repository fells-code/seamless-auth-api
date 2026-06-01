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
      challenge: 'challenge',
      challengeContext: { prfSalt: 'salt' },
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
    expect(user).not.toHaveProperty('challenge');
    expect(user).not.toHaveProperty('challengeContext');
    expect(user).not.toHaveProperty('emailVerificationToken');
    expect(user).not.toHaveProperty('phoneVerificationToken');
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
});
