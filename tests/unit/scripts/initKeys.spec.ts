import { vi } from 'vitest';

vi.mock('../../../src/scripts/keyManager', () => ({
  ensureKeys: vi.fn(),
}));

import { describe, it, expect } from 'vitest';

describe('init script', () => {
  it('calls ensureKeys on import', async () => {
    const { ensureKeys } = await import('../../../src/scripts/keyManager');

    await import('../../../src/scripts/initKeys');

    expect(ensureKeys).toHaveBeenCalled();
  });
});
