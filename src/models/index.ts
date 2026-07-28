/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { readdirSync } from 'fs';
import path from 'path';
import { Sequelize } from 'sequelize';
import { fileURLToPath } from 'url';

import { buildDatabaseUrl, resolveSslOptions } from '../config/database.cjs';
import getLogger from '../utils/logger.js';

const logger = getLogger('sequelize');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isProduction = process.env.NODE_ENV === 'production';
const enableDbLogging = !isProduction && process.env.DB_LOGGING === 'true';

let sequelizeInstance: Sequelize | null = null;

export function getSequelize(): Sequelize {
  if (sequelizeInstance) return sequelizeInstance;

  const testDbMode = process.env.TEST_DB;

  if (process.env.NODE_ENV === 'test' && testDbMode === 'sqlite') {
    logger.info('Using SQLite in-memory database for tests');

    sequelizeInstance = new Sequelize('sqlite::memory:', {
      logging: false,
    });

    return sequelizeInstance;
  }

  const DATABASE_URL = buildDatabaseUrl();
  const ssl = resolveSslOptions(DATABASE_URL);

  logger.info(`Using Postgres database (TLS ${ssl ? 'enabled' : 'disabled'})`);

  sequelizeInstance = new Sequelize(DATABASE_URL, {
    logging: enableDbLogging ? (msg) => logger.debug(msg) : false,
    ...(ssl ? { dialectOptions: { ssl } } : {}),
  });

  return sequelizeInstance;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const models: { [key: string]: any } = {};

export async function initializeModels() {
  const sequelize = getSequelize();

  const files = readdirSync(__dirname).filter((file) => {
    const ext = path.extname(file);
    return file.endsWith(ext) && file !== `index${ext}`;
  });

  const modelDefs = await Promise.all(
    files.map(async (file) => {
      const modelModule = await import(path.join(__dirname, file));

      if (!modelModule.default) {
        throw new Error(`Model file ${file} does not export default`);
      }

      return modelModule.default(sequelize);
    }),
  );

  for (const model of modelDefs) {
    models[model.name] = model;
  }

  for (const modelName of Object.keys(models)) {
    if (models[modelName].associate) {
      models[modelName].associate(models);
    }
  }

  models.sequelize = getSequelize();
  models.Sequelize = Sequelize;

  return models;
}

export { models };
