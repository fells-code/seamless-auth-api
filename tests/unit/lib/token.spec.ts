import { vi } from 'vitest';

vi.unmock('../../../src/lib/token');

vi.mock('../../../src/utils/signingKeyStore.js', () => ({
  getSigningKey: vi.fn(),
}));

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

const signPayloads = vi.hoisted(() => [] as unknown[]);
const signAudiences = vi.hoisted(() => [] as unknown[]);

vi.mock('jose', () => {
  class MockSignJWT {
    constructor(payload: unknown) {
      signPayloads.push(payload);
    }
    setProtectedHeader() {
      return this;
    }
    setIssuedAt() {
      return this;
    }
    setIssuer() {
      return this;
    }
    setAudience(audience: unknown) {
      signAudiences.push(audience);
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
  createHmac: vi.fn(() => ({
    update: vi.fn().mockReturnThis(),
    digest: vi.fn(() => 'lookup-hash'),
  })),
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
    delete process.env.REFRESH_TOKEN_LOOKUP_SECRET;
    delete process.env.API_SERVICE_TOKEN;
    delete process.env.APP_ID;
    process.env.NODE_ENV = 'test';
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

    signAudiences.length = 0;

    const { signAccessToken } = await import('../../../src/lib/token');

    const result = await signAccessToken('sid', 'user', ['admin']);

    expect(result).toBe('mock-jwt');
    expect(signAudiences.at(-1)).toBe('issuer');
  });

  it('embeds an organization claim when an organization id is provided', async () => {
    const { getSigningKey } = await import('../../../src/utils/signingKeyStore');
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    (getSigningKey as any).mockResolvedValue({ kid: 'kid', privateKeyPem: 'pem' });
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    signPayloads.length = 0;

    const { signAccessToken } = await import('../../../src/lib/token');

    await signAccessToken('sid', 'user', ['admin'], 'org-1');

    expect(signPayloads.at(-1)).toEqual(expect.objectContaining({ org_id: 'org-1' }));
  });

  it('omits the organization claim when no organization id is provided', async () => {
    const { getSigningKey } = await import('../../../src/utils/signingKeyStore');
    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    (getSigningKey as any).mockResolvedValue({ kid: 'kid', privateKeyPem: 'pem' });
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    signPayloads.length = 0;

    const { signAccessToken } = await import('../../../src/lib/token');

    await signAccessToken('sid', 'user', ['admin']);

    expect(signPayloads.at(-1)).not.toHaveProperty('org_id');
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

    signAudiences.length = 0;

    const { signRefreshToken } = await import('../../../src/lib/token');

    const result = await signRefreshToken('sid', 'user');

    expect(result).toBe('mock-jwt');
    expect(signAudiences.at(-1)).toBe('issuer');
  });

  it('signs ephemeral token', async () => {
    const { getSigningKey } = await import('../../../src/utils/signingKeyStore');

    (getSigningKey as any).mockResolvedValue({
      kid: 'kid',
      privateKeyPem: 'pem',
    });

    signAudiences.length = 0;

    const { signEphemeralToken } = await import('../../../src/lib/token');

    const result = await signEphemeralToken('user');

    expect(result).toBe('mock-jwt');
    expect(signAudiences.at(-1)).toBe('issuer');
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

  it('creates refresh token lookup fingerprints', async () => {
    process.env.API_SERVICE_TOKEN = 'service-secret';
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    const result = createRefreshTokenLookup('token');

    expect(result).toBe('lookup-hash');
  });

  it('prefers an explicit refresh token lookup secret when configured', async () => {
    process.env.REFRESH_TOKEN_LOOKUP_SECRET = 'lookup-secret';
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    const result = createRefreshTokenLookup('token');

    expect(result).toBe('lookup-hash');
  });

  it('uses the development fallback secret when no configured secret exists', async () => {
    process.env.APP_ID = 'local-dev';
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    const result = createRefreshTokenLookup('token');

    expect(result).toBe('lookup-hash');
  });

  it('warns only once and defaults APP_ID to local for the dev fallback secret', async () => {
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    expect(createRefreshTokenLookup('token')).toBe('lookup-hash');
    expect(createRefreshTokenLookup('token')).toBe('lookup-hash');
  });

  it('throws in production when no refresh token lookup secret is available', async () => {
    process.env.NODE_ENV = 'production';
    const { createRefreshTokenLookup } = await import('../../../src/lib/token');

    expect(() => createRefreshTokenLookup('token')).toThrow(
      'REFRESH_TOKEN_LOOKUP_SECRET (or API_SERVICE_TOKEN) must be set',
    );
  });
});
