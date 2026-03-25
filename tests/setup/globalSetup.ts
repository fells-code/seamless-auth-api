import { setupTestDb, teardownTestDb } from './db';

export default async () => {
  await setupTestDb();

  return async () => {
    await teardownTestDb();
  };
};
