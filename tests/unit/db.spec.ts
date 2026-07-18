import { beforeEach, describe, expect, it, vi } from 'vitest';

const loggerMock = {
  info: vi.fn(),
  error: vi.fn(),
};

// db.ts binds its logger at module-load time, so the logger mock must be registered before
// db.ts is imported. Using vi.doMock (not hoisted) plus resetModules guarantees the fresh
// import picks up the mock deterministically, even when this file shares a worker with
// specs that import the real logger.
describe('connectToDb', () => {
  beforeEach(() => {
    vi.resetModules();
    loggerMock.info.mockClear();
    loggerMock.error.mockClear();
    vi.doMock('../../src/utils/logger', () => ({ default: () => loggerMock }));
  });

  it('connects successfully and logs info', async () => {
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
