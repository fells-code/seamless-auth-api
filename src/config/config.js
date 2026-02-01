/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
module.exports = {
  development: {
    dialect: 'postgres',
    use_env_variable: 'DATABASE_URL',
    logging: 'false',
  },
  test: {
    dialect: 'postgres',
    use_env_variable: process.env.TEST_DATABASE_URL,
  },
  production: {
    dialect: 'postgres',
    use_env_variable: process.env.DATABASE_URL,
    logging: 'false',
  },
};
