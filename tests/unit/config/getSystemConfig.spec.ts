import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.unmock('../../../src/config/getSystemConfig');

function validRows(
  overrides: Record<string, unknown> = {},
): Array<{ key: string; value: unknown }> {
  const base: Record<string, unknown> = {
    app_name: 'TestApp',
    default_roles: ['user'],
    available_roles: ['user', 'admin'],
    access_token_ttl: '15m',
    refresh_token_ttl: '7d',
    rate_limit: 100,
    delay_after: 0,
    rpid: 'localhost',
    origins: ['https://example.com'],
    ...overrides,
  };
  return Object.entries(base).map(([key, value]) => ({ key, value }));
}

describe('getSystemConfig', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('fetches config from DB when cache empty', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any).mockResolvedValue(validRows({ app_name: 'TestApp' }));

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const result = await getSystemConfig();

    expect(SystemConfig.findAll).toHaveBeenCalled();
    expect(result.app_name).toBe('TestApp');
    expect(result.default_roles).toEqual(['user']);
  });

  it('returns cached config when within TTL', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any).mockResolvedValue(validRows({ app_name: 'TestApp' }));

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const first = await getSystemConfig();
    const second = await getSystemConfig();

    expect(SystemConfig.findAll).toHaveBeenCalledTimes(1);
    expect(second).toEqual(first);
  });

  it('refreshes cache after TTL expires', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any)
      .mockResolvedValueOnce(validRows({ app_name: 'AppA' }))
      .mockResolvedValueOnce(validRows({ app_name: 'AppB' }));

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    const first = await getSystemConfig();

    vi.spyOn(Date, 'now')
      .mockReturnValueOnce(Date.now() + 1)
      .mockReturnValueOnce(Date.now() + 6 * 60 * 1000);

    const second = await getSystemConfig();

    expect(second.app_name).toBe('AppB');
    expect(first.app_name).toBe('AppA');
    expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
  });

  it('invalidates cache manually', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findAll as any)
      .mockResolvedValueOnce(validRows({ app_name: 'AppA' }))
      .mockResolvedValueOnce(validRows({ app_name: 'AppB' }));

    const { getSystemConfig, invalidateSystemConfigCache } =
      await import('../../../src/config/getSystemConfig');

    await getSystemConfig();

    invalidateSystemConfigCache();

    const result = await getSystemConfig();

    expect(result.app_name).toBe('AppB');
    expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
  });

  describe('runtime schema validation (#13)', () => {
    // Drive the validation gate per-field so a future schema change that
    // weakens any single rule fails an obvious test instead of silently
    // shipping shape-mismatched config to downstream auth code.
    it.each<{ key: string; bad: unknown; reason: string }>([
      { key: 'app_name', bad: 'ab', reason: 'string shorter than min(3)' },
      { key: 'default_roles', bad: ['has space'], reason: 'role contains whitespace' },
      { key: 'default_roles', bad: [], reason: 'empty array' },
      { key: 'available_roles', bad: ['bad/role'], reason: 'role contains slash' },
      { key: 'access_token_ttl', bad: '15', reason: 'missing unit suffix' },
      { key: 'refresh_token_ttl', bad: '7days', reason: 'wrong unit format' },
      { key: 'rate_limit', bad: 0, reason: 'rate_limit must be positive' },
      { key: 'rate_limit', bad: -1, reason: 'rate_limit cannot be negative' },
      { key: 'rate_limit', bad: 1.5, reason: 'rate_limit must be int' },
      { key: 'delay_after', bad: -1, reason: 'delay_after cannot be negative' },
      { key: 'rpid', bad: '', reason: 'empty rpid' },
      { key: 'origins', bad: ['test'], reason: 'origins[i] must be a URL' },
      { key: 'origins', bad: 'https://example.com', reason: 'origins must be an array' },
      { key: 'origins', bad: [], reason: 'origins must have at least one entry' },
    ])('rejects $key when $reason', async ({ key, bad }) => {
      const { SystemConfig } = await import('../../../src/models/systemConfig');
      const rows = validRows({ [key]: bad });
      (SystemConfig.findAll as any).mockResolvedValue(rows);

      const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
      await expect(getSystemConfig()).rejects.toThrow('System configuration is invalid');
    });

    it('rejects when a required field row is missing entirely', async () => {
      const { SystemConfig } = await import('../../../src/models/systemConfig');
      const tainted = validRows().filter((row) => row.key !== 'default_roles');
      (SystemConfig.findAll as any).mockResolvedValue(tainted);

      const { getSystemConfig } = await import('../../../src/config/getSystemConfig');
      await expect(getSystemConfig()).rejects.toThrow('System configuration is invalid');
    });

    // After a tainted read the cache must remain empty so the next call
    // re-hits the DB. Otherwise the operator's recovery fix (correct row
    // value) wouldn't be picked up until process restart.
    it('keeps the cache empty after a failed validation so the next call reloads from DB', async () => {
      const { SystemConfig } = await import('../../../src/models/systemConfig');
      const tainted = validRows().filter((row) => row.key !== 'app_name');
      const recovered = validRows({ app_name: 'Recovered' });
      (SystemConfig.findAll as any).mockResolvedValueOnce(tainted).mockResolvedValueOnce(recovered);

      const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

      await expect(getSystemConfig()).rejects.toThrow();
      const result = await getSystemConfig();
      expect(result.app_name).toBe('Recovered');
      expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
    });
  });
});
