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
    app_name: 'APP_NAME',
    rate_limit: 'RATE_LIMIT',
  },
}));

vi.mock('../../../src/schemas/systemConfig.schema', () => ({
  SystemConfigSchema: {
    safeParse: vi.fn(),
  },
}));

function resetEnv() {
  delete process.env.APP_NAME;
  delete process.env.RATE_LIMIT;
}

import { describe, it, expect, beforeEach } from 'vitest';

describe('bootstrapSystemConfig', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    resetEnv();
  });

  it('uses existing config from DB', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');
    const { SystemConfigSchema } = await import('../../../src/schemas/systemConfig.schema');

    (SystemConfig.findByPk as any).mockResolvedValue({
      value: 'existing',
    });

    (SystemConfigSchema.safeParse as any).mockReturnValue({
      success: true,
      data: { app_name: 'existing', rate_limit: 'existing' },
    });

    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');

    const result = await bootstrapSystemConfig();

    expect(result).toBeDefined();
    expect(SystemConfig.create).not.toHaveBeenCalled();
  });

  it('creates config from env when missing', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');
    const { parseSystemConfigEnvValue } = await import('../../../src/utils/parseEnvConfigs');
    const { SystemConfigSchema } = await import('../../../src/schemas/systemConfig.schema');

    (SystemConfig.findByPk as any).mockResolvedValue(null);

    process.env.APP_NAME = 'TestApp';
    process.env.RATE_LIMIT = '100';

    (parseSystemConfigEnvValue as any).mockReturnValue('parsed');

    (SystemConfigSchema.safeParse as any).mockReturnValue({
      success: true,
      data: { app_name: 'parsed', rate_limit: 'parsed' },
    });

    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');

    const result = await bootstrapSystemConfig();

    expect(SystemConfig.create).toHaveBeenCalled();
    expect(result).toBeDefined();
  });

  it('throws when env missing', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');

    (SystemConfig.findByPk as any).mockResolvedValue(null);

    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');

    await expect(bootstrapSystemConfig()).rejects.toThrow('Missing required system config');
  });

  it('throws when schema invalid', async () => {
    const { SystemConfig } = await import('../../../src/models/systemConfig');
    const { parseSystemConfigEnvValue } = await import('../../../src/utils/parseEnvConfigs');
    const { SystemConfigSchema } = await import('../../../src/schemas/systemConfig.schema');

    (SystemConfig.findByPk as any).mockResolvedValue(null);

    process.env.APP_NAME = 'TestApp';
    process.env.RATE_LIMIT = '100';

    (parseSystemConfigEnvValue as any).mockReturnValue('parsed');

    (SystemConfigSchema.safeParse as any).mockReturnValue({
      success: false,
      error: { toString: () => 'invalid schema' },
    });

    const { bootstrapSystemConfig } = await import('../../../src/config/bootstrapSystemConfig');

    await expect(bootstrapSystemConfig()).rejects.toThrow('Invalid system configuration');
  });
});
