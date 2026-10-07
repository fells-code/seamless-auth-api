/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Application } from 'express';

import { createApp } from './app.js';
import { bootstrapSystemConfig } from './config/bootstrapSystemConfig.js';
import { connectToDb } from './db.js';
import { initializeModels } from './models/index.js';
import { startAuditMaintenance } from './services/auditRetention.js';
import { initializeMetadataService } from './services/metadataServiceBootstrap.js';
import { assertSchemaCurrent } from './services/schemaGuard.js';
import getLogger from './utils/logger.js';

const logger = getLogger('server');

const PORT = process.env.PORT || 5312;
const HOST = process.env.HOST || '0.0.0.0';

async function startServer() {
  try {
    const models = await initializeModels();

    await connectToDb(models);
    await assertSchemaCurrent(models.sequelize);
    await bootstrapSystemConfig();

    // After config is bootstrapped, since it decides whether attestation is
    // requested at all. Never throws: a metadata blob that cannot be fetched is
    // a degraded state, not a reason to refuse to start.
    await initializeMetadataService();

    const app: Application = await createApp();

    app.listen(PORT as number, HOST, () => {
      logger.info(`Server online.`);
    });

    startAuditMaintenance();
  } catch (err) {
    logger.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
