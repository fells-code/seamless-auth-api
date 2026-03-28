import { vi } from 'vitest';

vi.unmock('../../../src/utils/secretsStore');

import { describe, it, expect, beforeEach } from 'vitest';
import { getSecret } from '../../../src/utils/secretsStore';

// optional: spy logger
import getLogger from '../../../src/utils/logger';

describe('getSecret', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.TEST_SECRET;
  });

  it('returns secret when defined', async () => {
    process.env.TEST_SECRET = 'value';

    const result = await getSecret('TEST_SECRET');

    expect(result).toBe('value');
  });

  it('throws error when secret missing', async () => {
    const logger = getLogger('secret_store');
    const spy = vi.spyOn(logger, 'error');

    await expect(getSecret('MISSING_SECRET')).rejects.toThrow(
      'Secret "MISSING_SECRET" is not defined',
    );

    expect(spy).toHaveBeenCalledWith(expect.stringContaining('Missing required secret'));
  });
});
