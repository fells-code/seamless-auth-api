import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
    mkdirSync: vi.fn(),
    writeFileSync: vi.fn(),
  },
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn(),
}));

vi.mock('crypto', async () => {
  const actual = await vi.importActual<typeof import('crypto')>('crypto');
  return {
    ...actual,
    default: {
      ...actual,
      generateKeyPairSync: vi.fn(),
    },
    generateKeyPairSync: vi.fn(),
  };
});

vi.mock('../../../src/utils/secretsStore.js', () => ({
  getSecret: vi.fn(),
}));

vi.mock('../../../src/utils/logger.js', () => ({
  default: vi.fn(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  })),
}));

describe('signingKeyStore', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  describe('DEV mode', () => {
    it('generates dev key if none exists', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');
      const crypto = await import('crypto');

      (fs.existsSync as any).mockReturnValue(false);
      (fs.default.existsSync as any).mockReturnValue(false);
      (crypto.generateKeyPairSync as any).mockReturnValue({
        privateKey: 'PRIVATE_KEY',
        publicKey: 'PUBLIC_KEY',
      });
      (crypto.default.generateKeyPairSync as any).mockReturnValue({
        privateKey: 'PRIVATE_KEY',
        publicKey: 'PUBLIC_KEY',
      });

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getSigningKey();

      expect(fs.default.mkdirSync).toHaveBeenCalled();
      expect(fs.default.writeFileSync).toHaveBeenCalledTimes(2);
      expect(result.privateKeyPem).toBe('PRIVATE_KEY');
    });

    it('returns existing dev key', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');

      (fs.existsSync as any).mockReturnValueOnce(true).mockReturnValueOnce(true);
      (fs.default.existsSync as any).mockReturnValueOnce(true).mockReturnValueOnce(true);
      (fs.readFileSync as any).mockReturnValue('EXISTING_KEY');
      (fs.default.readFileSync as any).mockReturnValue('EXISTING_KEY');

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getSigningKey();

      expect(result.privateKeyPem).toBe('EXISTING_KEY');
    });

    it('generates when the dev key file is absent', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');
      const crypto = await import('crypto');

      const enoent = Object.assign(new Error('missing'), { code: 'ENOENT' });
      (fs.default.readFileSync as any).mockImplementation(() => {
        throw enoent;
      });
      (crypto.default.generateKeyPairSync as any).mockReturnValue({
        privateKey: 'PRIVATE_KEY',
        publicKey: 'PUBLIC_KEY',
      });

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getSigningKey();

      expect(result.privateKeyPem).toBe('PRIVATE_KEY');
    });

    it('does not treat an unreadable dev key file as a missing one', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');

      (fs.default.readFileSync as any).mockImplementation(() => {
        throw Object.assign(new Error('denied'), { code: 'EACCES' });
      });

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      await expect(getSigningKey()).rejects.toThrow('denied');
    });

    it('adopts the winner key when another process created it first', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');
      const crypto = await import('crypto');

      (fs.default.readFileSync as any)
        .mockImplementationOnce(() => {
          throw Object.assign(new Error('missing'), { code: 'ENOENT' });
        })
        .mockReturnValue('WINNER_KEY');
      (crypto.default.generateKeyPairSync as any).mockReturnValue({
        privateKey: 'LOSER_KEY',
        publicKey: 'LOSER_PUBLIC',
      });
      (fs.default.writeFileSync as any).mockImplementation(() => {
        throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      });

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getSigningKey();

      expect(result.privateKeyPem).toBe('WINNER_KEY');
    });

    it('propagates a write failure that is not a lost race', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');
      const crypto = await import('crypto');

      (fs.default.readFileSync as any).mockImplementation(() => {
        throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      });
      (crypto.default.generateKeyPairSync as any).mockReturnValue({
        privateKey: 'PRIVATE_KEY',
        publicKey: 'PUBLIC_KEY',
      });
      (fs.default.writeFileSync as any).mockImplementation(() => {
        throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
      });

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      await expect(getSigningKey()).rejects.toThrow('disk full');
    });

    it('returns dev public key', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');

      (fs.existsSync as any).mockReturnValue(true);
      (fs.default.existsSync as any).mockReturnValue(true);
      (fs.readFileSync as any).mockReturnValue('PUBLIC_KEY');
      (fs.default.readFileSync as any).mockReturnValue('PUBLIC_KEY');

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getPublicKeyByKid('dev-main');

      expect(result).toBe('PUBLIC_KEY');
    });

    it('returns null if dev public key missing', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');
      (fs.existsSync as any).mockReturnValue(false);
      (fs.default.existsSync as any).mockReturnValue(false);

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore.js');
      const result = await getPublicKeyByKid('dev-main');

      expect(result).toBeNull();
    });
  });

  describe('PROD mode', () => {
    it('loads signing key from secrets', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any).mockResolvedValueOnce('kid-1').mockResolvedValueOnce('PRIVATE_KEY');

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getSigningKey();

      expect(result.kid).toBe('kid-1');
      expect(result.privateKeyPem).toBe('PRIVATE_KEY');
    });

    it('caches signing key', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any).mockResolvedValueOnce('kid-1').mockResolvedValueOnce('PRIVATE_KEY');

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      await getSigningKey();
      await getSigningKey();

      expect(getSecret).toHaveBeenCalledTimes(2);
    });

    it('loads public keys and retrieves by kid', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any).mockResolvedValue(
        JSON.stringify({
          keys: [{ kid: 'k1', pem: 'PEM_KEY', createdAt: '' }],
        }),
      );

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getPublicKeyByKid('k1');

      expect(result).toBe('PEM_KEY');
    });

    it('returns null if public key not found', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any).mockResolvedValue(JSON.stringify({ keys: [] }));

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getPublicKeyByKid('missing');

      expect(result).toBeNull();
    });

    it('returns null when the public keys secret is missing', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any).mockResolvedValue(undefined);

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getPublicKeyByKid('any');

      expect(result).toBeNull();
    });

    it('returns null when the public keys secret is not valid JSON', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any).mockResolvedValue('not-json');

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore.js');

      const result = await getPublicKeyByKid('any');

      expect(result).toBeNull();
    });

    it('serves a cached public key without re-fetching within the TTL', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any).mockResolvedValue(
        JSON.stringify({ keys: [{ kid: 'k1', pem: 'PEM_KEY', createdAt: '' }] }),
      );

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore.js');

      const first = await getPublicKeyByKid('k1');
      const second = await getPublicKeyByKid('k1');

      expect(first).toBe('PEM_KEY');
      expect(second).toBe('PEM_KEY');
      expect(getSecret).toHaveBeenCalledTimes(1);
    });

    it('async-refreshes the signing key once the cache goes stale', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore.js');

      (getSecret as any)
        .mockResolvedValueOnce('kid-1')
        .mockResolvedValueOnce('PRIVATE_1')
        .mockResolvedValueOnce('kid-2')
        .mockResolvedValueOnce('PRIVATE_2');

      const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(1000);

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore.js');

      const first = await getSigningKey();
      expect(first.kid).toBe('kid-1');

      nowSpy.mockReturnValue(1000 + 6 * 60 * 1000);

      const second = await getSigningKey();
      expect(second.kid).toBe('kid-1');

      await new Promise((resolve) => setImmediate(resolve));

      expect(getSecret).toHaveBeenCalledTimes(4);

      nowSpy.mockRestore();
    });
  });
});
