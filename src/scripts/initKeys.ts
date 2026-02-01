/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { ensureKeys } from './keyManager.js';

async function init() {
  await ensureKeys();
}
init();
