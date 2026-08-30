import { vi } from 'vitest';

vi.mock('fs/promises', () => ({
  access: vi.fn(),
  mkdir: vi.fn(),
  writeFile: vi.fn(),
}));

vi.mock('crypto', async () => {
  const actual = await vi.importActual<typeof import('crypto')>('crypto');
  return {
    ...actual,
    generateKeyPairSync: vi.fn(),
  };
});

import { describe, it, expect, beforeEach } from 'vitest';

describe('keyManager', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    delete process.env.NODE_ENV;
  });

  it('runs dev key setup when not production', async () => {
    vi.stubEnv('NODE_ENV', 'development');

    const crypto = await import('crypto');
    const fsp = await import('fs/promises');

    (fsp.access as any).mockRejectedValue(new Error('ENOENT'));

    (crypto.generateKeyPairSync as any).mockReturnValue({
      publicKey: 'PUBLIC',
      privateKey: 'PRIVATE',
    });

    const { ensureKeys } = await import('../../../src/scripts/keyManager');

    await ensureKeys();

    expect(fsp.mkdir).toHaveBeenCalled();
    expect(fsp.writeFile).toHaveBeenCalledTimes(2);
  });

  it('does nothing in production', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    const { ensureKeys } = await import('../../../src/scripts/keyManager');

    await ensureKeys();

    // no filesystem interaction
    const fsp = await import('fs/promises');
    expect(fsp.mkdir).not.toHaveBeenCalled();
  });

  it('skips generation if keys already exist', async () => {
    vi.stubEnv('NODE_ENV', 'development');

    const fsp = await import('fs/promises');

    (fsp.access as any).mockResolvedValue(undefined);

    const { ensureKeys } = await import('../../../src/scripts/keyManager');

    await ensureKeys();

    expect(fsp.writeFile).not.toHaveBeenCalled();
  });

  it('generates keys when missing', async () => {
    vi.stubEnv('NODE_ENV', 'development');

    const crypto = await import('crypto');
    const fsp = await import('fs/promises');

    (fsp.access as any).mockRejectedValue(new Error('ENOENT'));

    (crypto.generateKeyPairSync as any).mockReturnValue({
      publicKey: 'PUBLIC_KEY',
      privateKey: 'PRIVATE_KEY',
    });

    const { ensureKeys } = await import('../../../src/scripts/keyManager');

    await ensureKeys();

    expect(fsp.writeFile).toHaveBeenCalledTimes(2);
  });
});
