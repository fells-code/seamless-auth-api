/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Application } from 'express';

import { createApp } from './app.js';
import { assertAuthSecrets } from './config/authSecrets.js';
import { bootstrapSystemConfig } from './config/bootstrapSystemConfig.js';
import { assertDevModeIsLocal } from './config/devModeGuard.js';
import { getSystemConfig } from './config/getSystemConfig.js';
import { assertServiceTokenConfig } from './config/serviceToken.js';
import { connectToDb } from './db.js';
import { initializeModels } from './models/index.js';
import { TotpCredential } from './models/totpCredentials.js';
import { startAuditMaintenance } from './services/auditRetention.js';
import { initializeMetadataService } from './services/metadataServiceBootstrap.js';
import { warnIfUnboundOAuthStateAllowed } from './services/oauthService.js';
import { assertSchemaCurrent } from './services/schemaGuard.js';
import getLogger from './utils/logger.js';
import { initDevSigningKey } from './utils/signingKeyStore.js';

const logger = getLogger('server');

const PORT = process.env.PORT || 5312;
const HOST = process.env.HOST || '0.0.0.0';

async function startServer() {
  try {
    // First, so conflicting service token env vars stop boot before anything connects.
    assertServiceTokenConfig();
    assertDevModeIsLocal();
    warnIfUnboundOAuthStateAllowed();

    const models = await initializeModels();

    await connectToDb(models);
    await assertSchemaCurrent(models.sequelize);
    await bootstrapSystemConfig();

    // After bootstrap, since which secrets are needed depends on the stored config.
    assertAuthSecrets(await getSystemConfig(), (await TotpCredential.count()) > 0);

    // After config is bootstrapped, since it decides whether attestation is
    // requested at all. Never throws: a metadata blob that cannot be fetched is
    // a degraded state, not a reason to refuse to start.
    await initializeMetadataService();

    // Before listening, so JWKS publishes the dev key from the first request rather
    // than after the first sign-in generates it.
    initDevSigningKey();

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
