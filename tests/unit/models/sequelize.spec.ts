import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const sequelizeConstructor = vi.fn();

vi.mock('sequelize', () => ({
  Sequelize: sequelizeConstructor,
}));

describe('getSequelize database URL building', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    delete process.env.DATABASE_URL;
    delete process.env.TEST_DB;
    process.env.NODE_ENV = 'development';
    process.env.DB_LOGGING = 'false';
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('percent-encodes DB user and password when building fallback DATABASE_URL', async () => {
    process.env.DB_HOST = 'db.internal';
    process.env.DB_PORT = '5432';
    process.env.DB_NAME = 'auth_db';
    process.env.DB_USER = 'review@admin';
    process.env.DB_PASSWORD = 'p@ss:wo/rd?with#symbols';

    const { getSequelize } = await import('../../../src/models/index.js');

    getSequelize();

    expect(sequelizeConstructor).toHaveBeenCalledWith(
      'postgres://review%40admin:p%40ss%3Awo%2Frd%3Fwith%23symbols@db.internal:5432/auth_db',
      expect.objectContaining({
        logging: false,
      }),
    );
  });

  it('uses DATABASE_URL as-is when provided', async () => {
    process.env.DATABASE_URL = 'postgres://already:encoded@example.com:5432/auth_db';

    const { getSequelize } = await import('../../../src/models/index.js');

    getSequelize();

    expect(sequelizeConstructor).toHaveBeenCalledWith(
      process.env.DATABASE_URL,
      expect.objectContaining({
        logging: false,
      }),
    );
  });
});
