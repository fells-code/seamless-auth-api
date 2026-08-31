import { vi } from 'vitest';

vi.mock('../../../src/models/systemConfig', () => ({
  SystemConfig: {
    findByPk: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../src/utils/parseEnvConfigs', () => ({
  parseSystemConfigEnvValue: vi.fn(),
}));

vi.mock('../../../src/config/systemConfig.envMap', () => ({
  SYSTEM_CONFIG_ENV_MAP: {
    login_methods: 'LOGIN_METHODS',
  },
}));

vi.mock('../../../src/schemas/systemConfig.schema', () => ({
  SystemConfigSchema: {
    safeParse: vi.fn(),
  },
}));

import { beforeEach, describe, expect, it } from 'vitest';

describe('bootstrapSystemConfig defaults', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    delete process.env.LOGIN_METHODS;
  });

  it('seeds a missing config row from SYSTEM_CONFIG_DEFAULTS when no env is set', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');
    const { parseSystemConfigEnvValue } = await import('../../../src/utils/parseEnvConfigs');
    const { SystemConfigSchema } = await import('../../../src/schemas/systemConfig.schema');

    (SystemConfig.findByPk as any).mockResolvedValue(null);
    (SystemConfigSchema.safeParse as any).mockReturnValue({
      success: true,
      data: { login_methods: ['passkey', 'magic_link'] },
    });

    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');
    const result = await bootstrapSystemConfig();

    expect(SystemConfig.create).toHaveBeenCalledWith({
      key: 'login_methods',
      value: ['passkey', 'magic_link'],
      updatedBy: null,
    });
    // The default path never parses env values.
    expect(parseSystemConfigEnvValue).not.toHaveBeenCalled();
    expect(result).toBeDefined();
  });
});

// system_config.value is JSONB NOT NULL, so seeding a null default would fail the
// insert and take the whole boot down. Caught in CI by a real container start
// rather than here, which is why the mocked path now asserts it too.
describe('bootstrapSystemConfig with a null default', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    delete process.env.LOGIN_METHODS;
  });

  it('resolves the value without writing a row the column would reject', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');
    const { SystemConfigSchema } = await import('../../../src/schemas/systemConfig.schema');

    vi.doMock('../../../src/config/systemConfig.defaults', () => ({
      SYSTEM_CONFIG_DEFAULTS: { login_methods: null },
    }));

    (SystemConfig.findByPk as any).mockResolvedValue(null);
    (SystemConfigSchema.safeParse as any).mockReturnValue({ success: true, data: {} });

    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');
    await bootstrapSystemConfig();

    expect(SystemConfig.create).not.toHaveBeenCalled();
  });

  it('removes an existing row when the environment turns the value off', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');
    const { parseSystemConfigEnvValue } = await import('../../../src/utils/parseEnvConfigs');
    const { SystemConfigSchema } = await import('../../../src/schemas/systemConfig.schema');

    const row = { value: 5, updatedBy: null, update: vi.fn(), destroy: vi.fn() };
    (SystemConfig.findByPk as any).mockResolvedValue(row);
    (parseSystemConfigEnvValue as any).mockReturnValue(null);
    (SystemConfigSchema.safeParse as any).mockReturnValue({ success: true, data: {} });
    process.env.LOGIN_METHODS = 'unlimited';

    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');
    await bootstrapSystemConfig();

    expect(row.destroy).toHaveBeenCalled();
    expect(row.update).not.toHaveBeenCalled();
  });
});
