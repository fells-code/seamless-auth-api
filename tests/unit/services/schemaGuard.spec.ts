import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  assertSchemaCurrent,
  findPendingMigrations,
  MIGRATIONS_DIR,
  PendingMigrationsError,
} from '../../../src/services/schemaGuard.js';

let dir: string;
const query = vi.fn();
const sequelize = { query } as never;

function respond({ table = true, applied = [] as string[] } = {}) {
  query.mockImplementation(async (sql: string) =>
    sql.includes('to_regclass')
      ? [{ name: table ? '"SequelizeMeta"' : null }]
      : applied.map((name) => ({ name })),
  );
}

beforeEach(async () => {
  vi.clearAllMocks();
  dir = await mkdtemp(join(tmpdir(), 'migrations-'));
  for (const file of ['20260101-a.cjs', '20260102-b.cjs', '20260103-c.cjs', 'README.md']) {
    await writeFile(join(dir, file), '');
  }
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('findPendingMigrations', () => {
  it('lists migration files the database has not applied, in order', async () => {
    respond({ applied: ['20260101-a.cjs'] });

    await expect(findPendingMigrations(sequelize, dir)).resolves.toEqual([
      '20260102-b.cjs',
      '20260103-c.cjs',
    ]);
  });

  it('treats a database without the migrations table as entirely unmigrated', async () => {
    respond({ table: false });

    await expect(findPendingMigrations(sequelize, dir)).resolves.toEqual([
      '20260101-a.cjs',
      '20260102-b.cjs',
      '20260103-c.cjs',
    ]);
    expect(query).toHaveBeenCalledTimes(1);
  });

  it('lets an older build start against a newer schema', async () => {
    respond({
      applied: ['20260101-a.cjs', '20260102-b.cjs', '20260103-c.cjs', '20260104-d.cjs'],
    });

    await expect(findPendingMigrations(sequelize, dir)).resolves.toEqual([]);
  });

  it('points at the migrations this build ships with', async () => {
    respond({ applied: [] });

    const pending = await findPendingMigrations(sequelize);

    expect(MIGRATIONS_DIR.replace(/\\/g, '/')).toMatch(/\/src\/migrations\/?$/);
    expect(pending).toContain('20251228014652-0001-init-db.cjs');
  });
});

describe('assertSchemaCurrent', () => {
  it('refuses to start while a migration is pending', async () => {
    respond({ applied: ['20260101-a.cjs', '20260102-b.cjs'] });

    const failure = await assertSchemaCurrent(sequelize, dir).catch((error) => error);

    expect(failure).toBeInstanceOf(PendingMigrationsError);
    expect(failure.pending).toEqual(['20260103-c.cjs']);
    expect(failure.message).toContain('1 pending migration(s), starting with 20260103-c.cjs');
  });

  it('passes a fully migrated schema', async () => {
    respond({ applied: ['20260101-a.cjs', '20260102-b.cjs', '20260103-c.cjs'] });

    await expect(assertSchemaCurrent(sequelize, dir)).resolves.toBeUndefined();
  });
});
