import { getSequelize } from '../../src/models/index.js';

export async function setupTestDb() {
  if (process.env.TEST_DB === 'postgres') {
    const sequelize = getSequelize();
    await sequelize.sync({ force: true });
  }
}

export async function teardownTestDb() {
  if (process.env.TEST_DB === 'postgres') {
    const sequelize = getSequelize();
    await sequelize.close();
  }
}
