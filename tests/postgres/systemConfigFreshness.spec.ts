import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { bootstrapSystemConfig } from '../../src/config/bootstrapSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

type ConfigModule = typeof import('../../src/config/getSystemConfig.js');

// Each import after resetModules is a separate cache, standing in for a separate replica.
async function instance(): Promise<ConfigModule> {
  vi.resetModules();
  const module = await import('../../src/config/getSystemConfig.js');
  const { initializeModels: init } = await import('../../src/models/index.js');
  await init();
  return module;
}

// Backdates updatedAt, as a replica with a slow clock would, to show it is not relied on.
async function setAppName(value: string) {
  await getSequelize().query(
    `UPDATE system_config SET value = to_jsonb(:value::text), "updatedAt" = now() - interval '1 day' WHERE key = 'app_name'`,
    { replacements: { value } },
  );
}

let now = 1_000_000;

beforeAll(async () => {
  await initializeModels();
  for (const [key, value] of Object.entries(
    buildSystemConfig({ frontend_url: 'http://localhost:5174' }),
  )) {
    await getSequelize().query(
      `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
       VALUES (:key, :value, now(), now())
       ON CONFLICT (key) DO NOTHING`,
      { replacements: { key, value: JSON.stringify(value) } },
    );
  }
  await bootstrapSystemConfig();
  vi.spyOn(Date, 'now').mockImplementation(() => now);
});

afterAll(async () => {
  vi.restoreAllMocks();
  await getSequelize().close();
});

describe('system_config freshness across instances', () => {
  it('shows a write made elsewhere once the check interval passes, even with a backdated updatedAt', async () => {
    await setAppName('BeforeWrite');
    const a = await instance();
    const b = await instance();

    expect((await a.getSystemConfig()).app_name).toBe('BeforeWrite');
    expect((await b.getSystemConfig()).app_name).toBe('BeforeWrite');

    await setAppName('AfterWrite');
    a.invalidateSystemConfigCache();

    expect((await a.getSystemConfig()).app_name).toBe('AfterWrite');
    expect((await b.getSystemConfig()).app_name).toBe('BeforeWrite');

    now += b.SYSTEM_CONFIG_CHECK_INTERVAL_MS;

    expect((await b.getSystemConfig()).app_name).toBe('AfterWrite');
  });

  it('keeps the cached copy while the stored rows are unchanged', async () => {
    const a = await instance();
    const first = await a.getSystemConfig();

    now += a.SYSTEM_CONFIG_CHECK_INTERVAL_MS;

    expect(await a.getSystemConfig()).toBe(first);
  });
});
