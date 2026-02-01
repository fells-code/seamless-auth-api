/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import getLogger from './utils/logger';

const logger = getLogger('db');

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const connectToDb = async (models: { [key: string]: any }) => {
  try {
    await models.sequelize.authenticate();
    logger.info('DB connection established.');
  } catch (error) {
    logger.error('Failed to connect or sync with the database:', error);
    throw error;
  }
};
