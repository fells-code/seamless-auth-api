/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { readdir } from 'fs/promises';
import { QueryTypes, Sequelize } from 'sequelize';
import { fileURLToPath } from 'url';

import getLogger from '../utils/logger.js';

const logger = getLogger('schema-guard');

// One level below the project root from both src/services and dist/services, which is
// where the image puts src/migrations alongside dist.
export const MIGRATIONS_DIR = fileURLToPath(new URL('../../src/migrations/', import.meta.url));

export class PendingMigrationsError extends Error {
  constructor(readonly pending: string[]) {
    super(
      `Database schema is behind this build: ${pending.length} pending migration(s), ` +
        `starting with ${pending[0]}. Run migrations before starting the server.`,
    );
    this.name = 'PendingMigrationsError';
  }
}

async function appliedMigrations(sequelize: Sequelize): Promise<Set<string> | null> {
  const [table] = await sequelize.query<{ name: string | null }>(
    `SELECT to_regclass('public."SequelizeMeta"')::text AS name`,
    { type: QueryTypes.SELECT },
  );

  if (!table?.name) return null;

  const rows = await sequelize.query<{ name: string }>('SELECT name FROM "SequelizeMeta"', {
    type: QueryTypes.SELECT,
  });

  return new Set(rows.map((row) => row.name));
}

export async function findPendingMigrations(
  sequelize: Sequelize,
  migrationsDir = MIGRATIONS_DIR,
): Promise<string[]> {
  const files = (await readdir(migrationsDir)).filter((file) => file.endsWith('.cjs')).sort();
  const applied = await appliedMigrations(sequelize);

  if (!applied) return files;

  const known = new Set(files);
  const unknown = [...applied].filter((name) => !known.has(name));

  // An older build started against a newer schema, which is what a rollback does. It
  // has to be allowed to boot, so it is only reported.
  if (unknown.length) {
    logger.warn(
      `Database has ${unknown.length} migration(s) this build does not know, newest ${unknown.sort().at(-1)}`,
    );
  }

  return files.filter((file) => !applied.has(file));
}

/**
 * Refuses to start against a schema that has not been migrated to this build.
 *
 * This is the guard the entrypoint's migration step used to be: a deploy that runs new
 * code against an old schema fails here instead of failing on the first query that
 * needs a new column. It costs one query on the connection startup already opened,
 * so it can stay on even when migrations are applied by a separate one-off task.
 */
export async function assertSchemaCurrent(sequelize: Sequelize, migrationsDir?: string) {
  const pending = await findPendingMigrations(sequelize, migrationsDir);

  if (pending.length) {
    throw new PendingMigrationsError(pending);
  }
}
