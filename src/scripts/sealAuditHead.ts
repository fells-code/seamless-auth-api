/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

/**
 * Signs the audit chain head with `AUDIT_CHAIN_KEY`: once after the key is first set on a
 * deployment that migrated without it, and again after the key is rotated. Refuses a
 * chain that does not verify. Run as `node dist/scripts/sealAuditHead.js` with the same
 * database environment as the server.
 */

import { getSequelize, initializeModels } from '../models/index.js';
import { sealAuditChainHead } from '../services/auditIntegrity.js';

try {
  await initializeModels();
  const head = await sealAuditChainHead();
  console.log(`Signed the audit chain head at seq ${head.seq} (hash ${head.hash ?? 'none'}).`);
} catch (err) {
  console.error(`Did not sign the audit chain head: ${(err as Error).message}`);
  process.exitCode = 1;
} finally {
  await getSequelize()
    .close()
    .catch(() => undefined);
}
