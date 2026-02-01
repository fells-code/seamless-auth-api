/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */

import getLogger from './logger';

const logger = getLogger('secret_store');

export async function getSecret(key: string): Promise<string> {
  const value = process.env[key];

  if (!value) {
    logger.error(`Missing required secret: ${key}`);
    throw new Error(
      `Secret "${key}" is not defined. Provide it via environment variables or implement a custom secret store.`,
    );
  }

  return value;
}
