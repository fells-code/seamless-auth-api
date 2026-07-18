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
