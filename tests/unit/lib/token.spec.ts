import { vi } from 'vitest';

vi.unmock('../../../src/config/getSystemConfig');
vi.unmock('../../../src/lib/token');
vi.unmock('../../../src/utils/signingKeyStore');

vi.mock('../../../src/utils/signingKeyStore', () => ({
  getSigningKey: vi.fn(),
}));

vi.mock('../../../src/config/getSystemConfig', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('jose', () => {
  class MockSignJWT {
    setProtectedHeader() {
      return this;
    }
    setIssuedAt() {
      return this;
    }
    setIssuer() {
      return this;
    }
    setExpirationTime() {
      return this;
    }
    sign() {
      return Promise.resolve('mock-jwt');
    }
  }

  return {
    importPKCS8: vi.fn(),
    SignJWT: MockSignJWT,
  };
});

vi.mock('crypto', () => ({
  randomBytes: vi.fn(() => ({
    toString: () => 'random-token',
  })),
}));

vi.mock('bcrypt-ts', () => ({
  hashSync: vi.fn(() => 'hashed-token'),
}));

import { describe, it, expect, beforeEach } from 'vitest';

describe('token utils', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    process.env.ISSUER = 'issuer';
  });

  it('signs access token', async () => {
    const { getSigningKey } = await import('../../../src/utils/signingKeyStore');
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    (getSigningKey as any).mockResolvedValue({
      kid: 'kid',
      privateKeyPem: 'pem',
    });

    (getSystemConfig as any).mockResolvedValue({
      access_token_ttl: '15m',
    });

    const { signAccessToken } = await import('../../../src/lib/token');

    const result = await signAccessToken('sid', 'user', ['admin']);

    expect(result).toBe('mock-jwt');
  });

  it('signs refresh token', async () => {
    const { getSigningKey } = await import('../../../src/utils/signingKeyStore');
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    (getSigningKey as any).mockResolvedValue({
      kid: 'kid',
      privateKeyPem: 'pem',
    });

    (getSystemConfig as any).mockResolvedValue({
      refresh_token_ttl: '1h',
    });

    const { signRefreshToken } = await import('../../../src/lib/token');

    const result = await signRefreshToken('sid', 'user');

    expect(result).toBe('mock-jwt');
  });

  it('signs ephemeral token', async () => {
    const { getSigningKey } = await import('../../../src/utils/signingKeyStore');

    (getSigningKey as any).mockResolvedValue({
      kid: 'kid',
      privateKeyPem: 'pem',
    });

    const { signEphemeralToken } = await import('../../../src/lib/token');

    const result = await signEphemeralToken('user');

    expect(result).toBe('mock-jwt');
  });

  it('throws if signing fails', async () => {
    const jose = await import('jose');

    vi.spyOn(jose.SignJWT.prototype, 'sign').mockImplementation(() => {
      throw new Error('fail');
    });

    const { signEphemeralToken } = await import('../../../src/lib/token');

    await expect(signEphemeralToken('user')).rejects.toThrow();
  });

  it('generates refresh token', async () => {
    const { generateRefreshToken } = await import('../../../src/lib/token');

    const result = generateRefreshToken();

    expect(result).toBe('random-token');
  });

  it('hashes refresh token', async () => {
    const { hashRefreshToken } = await import('../../../src/lib/token');

    const result = await hashRefreshToken('token');

    expect(result).toBe('hashed-token');
  });
});
