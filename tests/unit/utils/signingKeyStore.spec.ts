import { describe, it, expect, vi, beforeEach } from 'vitest';

function setupMocks() {
  vi.mock('fs', async () => {
    const actual = await vi.importActual<typeof import('fs')>('fs');
    return {
      ...actual,
      existsSync: vi.fn(),
      readFileSync: vi.fn(),
      mkdirSync: vi.fn(),
      writeFileSync: vi.fn(),
    };
  });

  vi.mock('crypto', async () => {
    const actual = await vi.importActual<typeof import('crypto')>('crypto');
    return {
      ...actual,
      generateKeyPairSync: vi.fn(),
    };
  });

  vi.mock('../../../src/utils/secretsStore', () => ({
    getSecret: vi.fn(),
  }));
}

describe('signingKeyStore', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    setupMocks();
  });

  //TODO: Come back and figure out these tests
  describe.skip('DEV mode', () => {
    it('generates dev key if none exists', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');
      const crypto = await import('crypto');

      (fs.existsSync as any).mockReturnValue(false);

      (crypto.generateKeyPairSync as any).mockReturnValue({
        privateKey: 'PRIVATE_KEY',
        publicKey: 'PUBLIC_KEY',
      });

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore');

      const result = await getSigningKey();

      expect(result.privateKeyPem).toBe('PRIVATE_KEY');
    });

    it('returns existing dev key', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');

      (fs.existsSync as any).mockReturnValue(true);
      (fs.readFileSync as any).mockReturnValue('EXISTING_KEY');

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore');

      const result = await getSigningKey();

      expect(result.privateKeyPem).toBe('EXISTING_KEY');
    });

    it('returns dev public key', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');

      (fs.existsSync as any).mockReturnValue(true);
      (fs.readFileSync as any).mockReturnValue('PUBLIC_KEY');

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

      const result = await getPublicKeyByKid('dev-main');

      expect(result).toBe('PUBLIC_KEY');
    });

    it('returns null if dev public key missing', async () => {
      process.env.NODE_ENV = 'development';

      const fs = await import('fs');
      (fs.existsSync as any).mockReturnValue(false);

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');
      const result = await getPublicKeyByKid('dev-main');

      expect(result).toBeNull();
    });
  });

  describe('PROD mode', () => {
    it('loads signing key from secrets', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore');

      (getSecret as any)
        .mockResolvedValueOnce('kid-1') // ACTIVE_KID
        .mockResolvedValueOnce('PRIVATE_KEY'); // private key

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore');

      const result = await getSigningKey();

      expect(result.kid).toBe('kid-1');
      expect(result.privateKeyPem).toBe('PRIVATE_KEY');
    });

    it('caches signing key', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore');

      (getSecret as any).mockResolvedValueOnce('kid-1').mockResolvedValueOnce('PRIVATE_KEY');

      const { getSigningKey } = await import('../../../src/utils/signingKeyStore');

      await getSigningKey();
      await getSigningKey();

      expect(getSecret).toHaveBeenCalledTimes(2); // only first load
    });

    it('loads public keys and retrieves by kid', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore');

      (getSecret as any).mockResolvedValue(
        JSON.stringify({
          keys: [{ kid: 'k1', pem: 'PEM_KEY', createdAt: '' }],
        }),
      );

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

      const result = await getPublicKeyByKid('k1');

      expect(result).toBe('PEM_KEY');
    });

    it('returns null if public key not found', async () => {
      process.env.NODE_ENV = 'production';

      const { getSecret } = await import('../../../src/utils/secretsStore');

      (getSecret as any).mockResolvedValue(JSON.stringify({ keys: [] }));

      const { getPublicKeyByKid } = await import('../../../src/utils/signingKeyStore');

      const result = await getPublicKeyByKid('missing');

      expect(result).toBeNull();
    });
  });
});
