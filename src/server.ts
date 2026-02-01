/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import 'dotenv/config';

import app from './app';
import { bootstrapSystemConfig } from './config/bootstrapSystemConfig';
import { connectToDb } from './db';
import { initializeModels } from './models';
import getLogger from './utils/logger';

const logger = getLogger('server');

const PORT = process.env.PORT || 5312;
const HOST = process.env.HOST || '0.0.0.0';

async function startServer() {
  try {
    const models = await initializeModels();

    await connectToDb(models);
    await bootstrapSystemConfig();

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
