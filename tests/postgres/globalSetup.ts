import '../setup/env.js';

import { execFileSync } from 'child_process';
import { createRequire } from 'module';
import pg from 'pg';

const require = createRequire(import.meta.url);
const { buildDatabaseUrl } = require('../../src/config/database.cjs');

// Builds the schema the way a deployment does, by running the migration chain, so the
// triggers and functions the migrations create are the ones under test.
export default async () => {
  const client = new pg.Client({ connectionString: buildDatabaseUrl() });
  await client.connect();
  try {
    const { rows } = await client.query('SELECT current_database() AS name');

    // The schema is dropped next, so a database that is not obviously disposable is refused.
    if (!/test/i.test(rows[0].name)) {
      throw new Error(
        `Refusing to reset database "${rows[0].name}": its name must contain "test".`,
      );
    }

    await client.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  } finally {
    await client.end();
  }

  execFileSync(process.execPath, [require.resolve('sequelize-cli/lib/sequelize'), 'db:migrate'], {
    env: { ...process.env, NODE_ENV: 'test' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
};
