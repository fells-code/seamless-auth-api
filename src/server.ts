/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import 'dotenv/config';

import { Application } from 'express';

import { createApp } from './app.js';
import { bootstrapSystemConfig } from './config/bootstrapSystemConfig.js';
import { connectToDb } from './db.js';
import { initializeModels } from './models/index.js';
import getLogger from './utils/logger.js';

const logger = getLogger('server');

const PORT = process.env.PORT || 5312;
const HOST = process.env.HOST || '0.0.0.0';

async function startServer() {
  try {
    const models = await initializeModels();

    await connectToDb(models);
    await bootstrapSystemConfig();

    const app: Application = await createApp();

    app.listen(PORT as number, HOST, () => {
      logger.info(`Server online.`);
      logger.info(`Running in ${process.env.AUTH_MODE} auth mode`);
    });
  } catch (err) {
    logger.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
