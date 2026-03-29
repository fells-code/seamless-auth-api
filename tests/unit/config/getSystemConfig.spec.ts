import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.unmock('../../../src/config/getSystemConfig');

describe('getSystemConfig', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('fetches config from DB when cache empty', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any).mockResolvedValue([{ key: 'app_name', value: 'TestApp' }]);

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const result = await getSystemConfig();

    expect(SystemConfig.findAll).toHaveBeenCalled();
    expect(result).toEqual({ app_name: 'TestApp' });
  });

  it('returns cached config when within TTL', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any).mockResolvedValue([{ key: 'app_name', value: 'TestApp' }]);

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const first = await getSystemConfig();
    const second = await getSystemConfig();

    expect(SystemConfig.findAll).toHaveBeenCalledTimes(1);
    expect(second).toEqual(first);
  });

  it('refreshes cache after TTL expires', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any)
      .mockResolvedValueOnce([{ key: 'app_name', value: 'A' }])
      .mockResolvedValueOnce([{ key: 'app_name', value: 'B' }]);

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const first = await getSystemConfig();

    // simulate time passing
    vi.spyOn(Date, 'now')
      .mockReturnValueOnce(Date.now() + 1)
      .mockReturnValueOnce(Date.now() + 400_000); // > TTL

    const second = await getSystemConfig();

    expect(second).not.toEqual(first);
    expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
  });

  it('invalidates cache manually', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any)
      .mockResolvedValueOnce([{ key: 'app_name', value: 'A' }])
      .mockResolvedValueOnce([{ key: 'app_name', value: 'B' }]);

    const { getSystemConfig, invalidateSystemConfigCache } =
      await import('../../../src/config/getSystemConfig');

    await getSystemConfig();

    invalidateSystemConfigCache();

    const result = await getSystemConfig();

    expect(result).toEqual({ app_name: 'B' });
    expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
  });
});
