import { createRequire } from 'module';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  buildDatabaseUrl,
  parseDatabaseUrl,
  resolveDatabaseUrl,
  resolveSslOptions,
} from '../../../src/config/database.cjs';

const DB_VARS = [
  'DATABASE_URL',
  'DB_URI',
  'DB_HOST',
  'DB_PORT',
  'DB_NAME',
  'DB_USER',
  'DB_PASSWORD',
  'DB_SSL',
  'DB_SSL_CA',
  'DB_SSL_REJECT_UNAUTHORIZED',
];

describe('database connection resolution', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    for (const name of DB_VARS) delete process.env[name];
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('prefers DATABASE_URL, then DB_URI, then the discrete vars', () => {
    process.env.DB_HOST = 'db.internal';
    process.env.DB_PORT = '5432';
    process.env.DB_NAME = 'auth_db';
    process.env.DB_USER = 'auth';

    expect(resolveDatabaseUrl()).toBe('postgres://auth:@db.internal:5432/auth_db');

    process.env.DB_URI = 'postgres://uri:pass@uri.example.com:5432/auth_db';
    expect(resolveDatabaseUrl()).toBe(process.env.DB_URI);

    process.env.DATABASE_URL = 'postgres://url:pass@url.example.com:5432/auth_db';
    expect(resolveDatabaseUrl()).toBe(process.env.DATABASE_URL);
  });

  it('returns null and throws only from buildDatabaseUrl when vars are missing', () => {
    expect(resolveDatabaseUrl()).toBeNull();
    expect(() => buildDatabaseUrl()).toThrow('Missing required DB environment variables.');
  });

  it('round-trips percent-encoded credentials', () => {
    process.env.DB_HOST = 'db.internal';
    process.env.DB_PORT = '5432';
    process.env.DB_NAME = 'auth_db';
    process.env.DB_USER = 'review@admin';
    process.env.DB_PASSWORD = 'p@ss:wo/rd?with#symbols';

    const url = buildDatabaseUrl();

    expect(url).toBe(
      'postgres://review%40admin:p%40ss%3Awo%2Frd%3Fwith%23symbols@db.internal:5432/auth_db',
    );
    expect(parseDatabaseUrl(url)).toEqual({
      host: 'db.internal',
      port: '5432',
      database: 'auth_db',
      username: 'review@admin',
      password: 'p@ss:wo/rd?with#symbols',
    });
  });

  it('returns null for an unparseable connection string', () => {
    expect(parseDatabaseUrl('not-a-url')).toBeNull();
  });
});

describe('database TLS resolution', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    for (const name of DB_VARS) delete process.env[name];
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('leaves TLS off by default', () => {
    expect(resolveSslOptions('postgres://auth@db.internal:5432/auth_db')).toBeNull();
  });

  it('enables TLS without certificate verification for DB_SSL=true', () => {
    process.env.DB_SSL = 'true';

    expect(resolveSslOptions(null)).toEqual({ rejectUnauthorized: false });
  });

  it('honors an sslmode carried on the connection string', () => {
    expect(resolveSslOptions('postgres://auth@db.internal:5432/auth_db?sslmode=require')).toEqual({
      rejectUnauthorized: false,
    });

    expect(
      resolveSslOptions('postgres://auth@db.internal:5432/auth_db?sslmode=verify-full'),
    ).toEqual({ rejectUnauthorized: true });
  });

  it('lets DB_SSL override the connection string sslmode', () => {
    process.env.DB_SSL = 'false';

    expect(
      resolveSslOptions('postgres://auth@db.internal:5432/auth_db?sslmode=require'),
    ).toBeNull();
  });

  it('verifies the server certificate when a CA bundle is supplied', () => {
    process.env.DB_SSL = 'true';
    process.env.DB_SSL_CA = '-----BEGIN CERTIFICATE-----\nrds\n-----END CERTIFICATE-----';

    expect(resolveSslOptions(null)).toEqual({
      ca: process.env.DB_SSL_CA,
      rejectUnauthorized: true,
    });
  });

  it('lets DB_SSL_REJECT_UNAUTHORIZED override the default', () => {
    process.env.DB_SSL = 'verify-full';
    process.env.DB_SSL_REJECT_UNAUTHORIZED = 'false';

    expect(resolveSslOptions(null)).toEqual({ rejectUnauthorized: false });
  });

  it('fails loudly on an unsupported mode', () => {
    process.env.DB_SSL = 'maybe';

    expect(() => resolveSslOptions(null)).toThrow('Unsupported DB SSL mode: maybe');
  });
});

describe('sequelize-cli config', () => {
  const originalEnv = process.env;
  const require = createRequire(import.meta.url);
  const configPath = require.resolve('../../../src/config/config.cjs');

  function loadConfig() {
    delete require.cache[configPath];
    delete require.cache[require.resolve('../../../src/config/database.cjs')];
    return require(configPath);
  }

  beforeEach(() => {
    process.env = { ...originalEnv };
    for (const name of DB_VARS) delete process.env[name];
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('expands a connection string into discrete fields and applies TLS', () => {
    process.env.DB_URI = 'postgres://review%40admin:secret@db.internal:5432/auth_db';
    process.env.DB_SSL = 'true';

    expect(loadConfig().production).toEqual({
      host: 'db.internal',
      port: '5432',
      database: 'auth_db',
      username: 'review@admin',
      password: 'secret',
      dialect: 'postgres',
      dialectOptions: { ssl: { rejectUnauthorized: false } },
      logging: false,
    });
  });

  it('falls back to the discrete vars and omits dialectOptions when TLS is off', () => {
    process.env.DB_HOST = 'localhost';

    expect(loadConfig().production).toEqual({
      host: 'localhost',
      port: undefined,
      database: undefined,
      username: undefined,
      password: undefined,
      dialect: 'postgres',
      logging: false,
    });
  });
});
