import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

vi.unmock('../../../src/config/getSystemConfig');

const rowsFrom = (config: Record<string, unknown>) =>
  Object.entries(config).map(([key, value]) => ({ key, value }));

async function load() {
  const { SystemConfig } = await import('../../../src/models/systemConfig');
  const module = await import('../../../src/config/getSystemConfig');
  const findAll = SystemConfig.findAll as any;
  const query = SystemConfig.sequelize!.query as any;
  query.mockResolvedValue([{ fingerprint: 'v1' }]);
  return { ...module, findAll, query };
}

describe('getSystemConfig', () => {
  let now = 1_000_000;

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    now = 1_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('fetches and validates config from DB when cache empty', async () => {
    const { getSystemConfig, findAll, query } = await load();
    findAll.mockResolvedValue(rowsFrom(buildSystemConfig()));

    const result = await getSystemConfig();

    expect(query).toHaveBeenCalledWith(expect.stringContaining('md5'), { type: 'SELECT' });
    expect(findAll).toHaveBeenCalledTimes(1);
    expect(result.app_name).toBe('SeamlessAuth');
    expect(result.default_roles).toEqual(['user']);
  });

  it('throws when the stored config fails schema validation', async () => {
    const { getSystemConfig, findAll } = await load();
    findAll.mockResolvedValue([{ key: 'app_name', value: 'ab' }]);

    await expect(getSystemConfig()).rejects.toThrow(/Invalid system_config/);
  });

  it('serves from memory without a query inside the check interval', async () => {
    const { getSystemConfig, findAll, query, SYSTEM_CONFIG_CHECK_INTERVAL_MS } = await load();
    findAll.mockResolvedValue(rowsFrom(buildSystemConfig()));

    const first = await getSystemConfig();
    now += SYSTEM_CONFIG_CHECK_INTERVAL_MS - 1;
    const second = await getSystemConfig();

    expect(second).toBe(first);
    expect(query).toHaveBeenCalledTimes(1);
    expect(findAll).toHaveBeenCalledTimes(1);
  });

  it('keeps the cached copy when the fingerprint is unchanged', async () => {
    const { getSystemConfig, findAll, query, SYSTEM_CONFIG_CHECK_INTERVAL_MS } = await load();
    findAll.mockResolvedValue(rowsFrom(buildSystemConfig()));

    const first = await getSystemConfig();
    now += SYSTEM_CONFIG_CHECK_INTERVAL_MS;
    const second = await getSystemConfig();

    expect(second).toBe(first);
    expect(query).toHaveBeenCalledTimes(2);
    expect(findAll).toHaveBeenCalledTimes(1);
  });

  it('reloads within the check interval when another instance changes the config', async () => {
    const { getSystemConfig, findAll, query, SYSTEM_CONFIG_CHECK_INTERVAL_MS } = await load();
    findAll
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppOne' })))
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppTwo' })));

    expect((await getSystemConfig()).app_name).toBe('AppOne');

    query.mockResolvedValue([{ fingerprint: 'v2' }]);
    now += SYSTEM_CONFIG_CHECK_INTERVAL_MS;

    expect((await getSystemConfig()).app_name).toBe('AppTwo');
    expect(findAll).toHaveBeenCalledTimes(2);
  });

  it('treats an empty fingerprint result as an empty table', async () => {
    const { getSystemConfig, findAll, query } = await load();
    query.mockResolvedValue([]);
    findAll.mockResolvedValue(rowsFrom(buildSystemConfig()));

    await expect(getSystemConfig()).resolves.toMatchObject({ app_name: 'SeamlessAuth' });
  });

  it('fails closed when the fingerprint cannot be read once the interval has passed', async () => {
    const { getSystemConfig, findAll, query, SYSTEM_CONFIG_CHECK_INTERVAL_MS } = await load();
    findAll.mockResolvedValue(rowsFrom(buildSystemConfig()));
    await getSystemConfig();

    query.mockRejectedValueOnce(new Error('connection terminated'));
    now += SYSTEM_CONFIG_CHECK_INTERVAL_MS;

    await expect(getSystemConfig()).rejects.toThrow('connection terminated');

    // The failed check did not extend the cached copy, so the next call checks again.
    await expect(getSystemConfig()).resolves.toMatchObject({ app_name: 'SeamlessAuth' });
    expect(query).toHaveBeenCalledTimes(3);
  });

  it('shares one load between concurrent callers', async () => {
    const { getSystemConfig, findAll, query } = await load();
    findAll.mockResolvedValue(rowsFrom(buildSystemConfig()));

    const [a, b] = await Promise.all([getSystemConfig(), getSystemConfig()]);

    expect(a).toBe(b);
    expect(query).toHaveBeenCalledTimes(1);
    expect(findAll).toHaveBeenCalledTimes(1);
  });

  it('invalidates cache manually', async () => {
    const { getSystemConfig, invalidateSystemConfigCache, findAll } = await load();
    findAll
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppOne' })))
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AppTwo' })));

    await getSystemConfig();
    invalidateSystemConfigCache();

    expect((await getSystemConfig()).app_name).toBe('AppTwo');
    expect(findAll).toHaveBeenCalledTimes(2);
  });

  it('does not let a load started before an invalidation repopulate the cache', async () => {
    const { getSystemConfig, invalidateSystemConfigCache, findAll } = await load();
    let release!: (rows: unknown) => void;
    findAll
      .mockReturnValueOnce(new Promise((resolve) => (release = resolve)))
      .mockResolvedValueOnce(rowsFrom(buildSystemConfig({ app_name: 'AfterWrite' })));

    const stale = getSystemConfig();
    await vi.waitFor(() => expect(findAll).toHaveBeenCalledTimes(1));

    invalidateSystemConfigCache();
    const fresh = getSystemConfig();

    release(rowsFrom(buildSystemConfig({ app_name: 'BeforeWrite' })));

    expect((await stale).app_name).toBe('BeforeWrite');
    expect((await fresh).app_name).toBe('AfterWrite');
    expect((await getSystemConfig()).app_name).toBe('AfterWrite');
  });
});
