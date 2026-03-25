/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { readdirSync } from 'fs';
import path from 'path';
import { Sequelize } from 'sequelize';
import { fileURLToPath } from 'url';

import getLogger from '../utils/logger.js';

const logger = getLogger('sequelize');
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isProduction = process.env.NODE_ENV === 'production';
const enableDbLogging = !isProduction && process.env.DB_LOGGING === 'true';
const { DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD } = process.env;

const DATABASE_URL = `postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}`;

export const sequelize = new Sequelize(DATABASE_URL, {
  logging: enableDbLogging ? (msg) => logger.debug(msg) : false,
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const models: { [key: string]: any } = {};

export async function initializeModels() {
  const files = readdirSync(__dirname).filter((file) => {
    const ext = path.extname(file);
    return file.endsWith(ext) && file !== `index${ext}`;
  });

  const modelDefs = await Promise.all(
    files.map(async (file) => {
      const modelModule = await import(path.join(__dirname, file));
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

  models.sequelize = sequelize;
  models.Sequelize = Sequelize;

  return models;
}
