import { vi } from 'vitest';

vi.mock('../../../src/models/systemConfig', () => ({
  SystemConfig: {
    findByPk: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../src/config/systemConfig.envMap', () => ({
  SYSTEM_CONFIG_ENV_MAP: {
    max_concurrent_sessions: 'MAX_CONCURRENT_SESSIONS',
  },
}));

vi.mock('../../../src/schemas/systemConfig.schema', () => ({
  SystemConfigSchema: {
    safeParse: vi.fn(),
  },
}));

import { beforeEach, describe, expect, it } from 'vitest';

// The real parser and defaults are used here. Bootstrap skips an empty env value
// before parsing, so MAX_CONCURRENT_SESSIONS='' behaves as unset rather than as
// "no limit". Only a whitespace-only value reaches the parser's empty check.
describe('bootstrapSystemConfig with MAX_CONCURRENT_SESSIONS', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    delete process.env.MAX_CONCURRENT_SESSIONS;
  });

  async function load() {
    const { SystemConfig } = await import('../../../src/models/systemConfig');
    const { SystemConfigSchema } = await import('../../../src/schemas/systemConfig.schema');
    (SystemConfigSchema.safeParse as any).mockReturnValue({ success: true, data: {} });
    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');
    return { SystemConfig, SystemConfigSchema, bootstrapSystemConfig };
  }

  it('keeps an existing cap when the value is empty', async () => {
    const { SystemConfig, SystemConfigSchema, bootstrapSystemConfig } = await load();
    const row = { value: 3, updatedBy: null, update: vi.fn(), destroy: vi.fn() };
    (SystemConfig.findByPk as any).mockResolvedValue(row);
    process.env.MAX_CONCURRENT_SESSIONS = '';

    await bootstrapSystemConfig();

    expect(row.update).not.toHaveBeenCalled();
    expect(row.destroy).not.toHaveBeenCalled();
    expect(SystemConfigSchema.safeParse).toHaveBeenCalledWith({ max_concurrent_sessions: 3 });
  });

  it('uses the default when the value is empty and no row exists', async () => {
    const { SystemConfig, SystemConfigSchema, bootstrapSystemConfig } = await load();
    (SystemConfig.findByPk as any).mockResolvedValue(null);
    process.env.MAX_CONCURRENT_SESSIONS = '';

    await bootstrapSystemConfig();

    expect(SystemConfig.create).not.toHaveBeenCalled();
    expect(SystemConfigSchema.safeParse).toHaveBeenCalledWith({ max_concurrent_sessions: null });
  });

  it('clears an existing cap when the value is whitespace only', async () => {
    const { SystemConfig, SystemConfigSchema, bootstrapSystemConfig } = await load();
    const row = { value: 3, updatedBy: null, update: vi.fn(), destroy: vi.fn() };
    (SystemConfig.findByPk as any).mockResolvedValue(row);
    process.env.MAX_CONCURRENT_SESSIONS = '   ';

    await bootstrapSystemConfig();

    expect(row.destroy).toHaveBeenCalled();
    expect(row.update).not.toHaveBeenCalled();
    expect(SystemConfigSchema.safeParse).toHaveBeenCalledWith({ max_concurrent_sessions: null });
  });
});
