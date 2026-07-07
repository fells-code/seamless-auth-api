import { vi } from 'vitest';
vi.unmock('../../src/utils/logger');
const loggerMock = {
  info: vi.fn(),
  error: vi.fn(),
};

vi.mock('../../src/utils/logger', () => ({
  default: () => loggerMock,
}));

import { describe, it, expect, beforeEach } from 'vitest';

describe('connectToDb', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('connects successfully and logs info', async () => {
    const logger = (await import('../../src/utils/logger')).default('test');
    const { connectToDb } = await import('../../src/db');

    const models = {
      sequelize: {
        authenticate: vi.fn().mockResolvedValue(undefined),
      },
    };

    await connectToDb(models);

    expect(models.sequelize.authenticate).toHaveBeenCalled();
    expect(loggerMock.info).toHaveBeenCalledWith('DB connection established.');
  });

  it('logs error and throws when connection fails', async () => {
    const { connectToDb } = await import('../../src/db');

    const error = new Error('connection failed');

    const models = {
      sequelize: {
        authenticate: vi.fn().mockRejectedValue(error),
      },
    };

    await expect(connectToDb(models)).rejects.toThrow('connection failed');

    expect(loggerMock.error).toHaveBeenCalledWith(
      'Failed to connect or sync with the database:',
      error,
    );
  });
});
