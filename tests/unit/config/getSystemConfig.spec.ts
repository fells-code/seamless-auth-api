import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.unmock('../../../src/config/getSystemConfig');

// Build a full set of valid `system_config` rows that satisfies
// `SystemConfigSchema`. The runtime read path now validates against
// the schema (#13), so partial `{ app_name: ... }` payloads no longer
// round-trip — every row must be present.
function validRows(overrides: Record<string, unknown> = {}): Array<{ key: string; value: unknown }> {
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

    // simulate time passing past the cache TTL
    vi.spyOn(Date, 'now')
      .mockReturnValueOnce(Date.now() + 1)
      .mockReturnValueOnce(Date.now() + 6 * 60 * 1000); // > 5 min TTL

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

  // Regression for https://github.com/fells-code/seamless-auth-api/issues/13.
  // The runtime read path must schema-validate the rows it pulls from
  // the DB and refuse to hand out tainted config. Partial / malformed
  // rows that previously slipped through the bare cast now throw.
  it('throws when DB rows fail schema validation', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    // Drop a required field — `default_roles` — so schema validation fails.
    const tainted = validRows().filter((row) => row.key !== 'default_roles');
    (SystemConfig.findAll as any).mockResolvedValue(tainted);

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    await expect(getSystemConfig()).rejects.toThrow('System configuration is invalid');
  });

  it('does not cache a tainted result', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    const tainted = validRows().filter((row) => row.key !== 'app_name');
    const valid = validRows({ app_name: 'Recovered' });
    (SystemConfig.findAll as any)
      .mockResolvedValueOnce(tainted)
      .mockResolvedValueOnce(valid);

    const { getSystemConfig } = await import('../../../src/config/getSystemConfig');

    await expect(getSystemConfig()).rejects.toThrow();

    // After the operator fixes the row, the next call must hit the DB
    // again (no stale "tainted" entry sitting in cache) and succeed.
    const result = await getSystemConfig();
    expect(result.app_name).toBe('Recovered');
    expect(SystemConfig.findAll).toHaveBeenCalledTimes(2);
  });
});
