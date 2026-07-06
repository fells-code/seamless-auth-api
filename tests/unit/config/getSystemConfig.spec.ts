import { describe, it, expect, vi, beforeEach } from 'vitest';

import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

vi.unmock('../../../src/config/getSystemConfig');

const rowsFrom = (config: Record<string, unknown>) =>
  Object.entries(config).map(([key, value]) => ({ key, value }));

describe('getSystemConfig', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('fetches and validates config from DB when cache empty', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any).mockResolvedValue(rowsFrom(buildSystemConfig()));

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const result = await getSystemConfig();

    expect(SystemConfig.findAll).toHaveBeenCalled();
    expect(result.app_name).toBe('SeamlessAuth');
    expect(result.default_roles).toEqual(['user']);
  });

  it('throws when the stored config fails schema validation', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any).mockResolvedValue([{ key: 'app_name', value: 'ab' }]);

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    await expect(getSystemConfig()).rejects.toThrow(/Invalid system_config/);
  });

  it('returns cached config when within TTL', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any).mockResolvedValue(rowsFrom(buildSystemConfig()));

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const first = await getSystemConfig();
    const second = await getSystemConfig();

    expect(SystemConfig.findAll).toHaveBeenCalledTimes(1);
    expect(second).toEqual(first);
  });

  it('refreshes cache after TTL expires', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any)
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppOne' })))
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppTwo' })));

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const first = await getSystemConfig();

    // simulate time passing
    vi.spyOn(Date, 'now')
      .mockReturnValueOnce(Date.now() + 1)
      .mockReturnValueOnce(Date.now() + 400_000); // > TTL

    const second = await getSystemConfig();

    expect(second.app_name).not.toBe(first.app_name);
    expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
  });

  it('invalidates cache manually', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any)
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppOne' })))
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppTwo' })));

    const { getSystemConfig, invalidateSystemConfigCache } =
      await import('../../../src/config/getSystemConfig');

    await getSystemConfig();

    invalidateSystemConfigCache();

    const result = await getSystemConfig();

    expect(result.app_name).toBe('AppTwo');
    expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
  });
});
