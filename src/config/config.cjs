/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

const { parseDatabaseUrl, resolveDatabaseUrl, resolveSslOptions } = require('./database.cjs');

function dbLoggingOption() {
  if (process.env.DB_LOGGING !== 'true') {
    return false;
  }

  return (sql) => console.debug(sql);
}

// sequelize-cli parses a `url` key without percent-decoding credentials, so the
// connection string is expanded here instead and handed over as discrete fields.
function connectionSettings() {
  const url = resolveDatabaseUrl();
  const parsed = url ? parseDatabaseUrl(url) : null;

  if (parsed) {
    return parsed;
  }

  return {
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
  };
}

function databaseConfig(extra = {}) {
  const ssl = resolveSslOptions(resolveDatabaseUrl());

  return {
    ...connectionSettings(),
    dialect: 'postgres',
    ...(ssl ? { dialectOptions: { ssl } } : {}),
    ...extra,
  };
}

module.exports = {
  development: databaseConfig({ logging: dbLoggingOption() }),
  test: databaseConfig(),
  production: databaseConfig({ logging: dbLoggingOption() }),
};
