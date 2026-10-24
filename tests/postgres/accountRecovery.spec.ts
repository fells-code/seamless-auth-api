import { randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { AccountRecoveryRequest } from '../../src/models/accountRecoveryRequests.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import {
  cancelRecoveryByToken,
  completeRecovery,
  findRecoveryForAttempt,
  startRecovery,
  verifyRecovery,
} from '../../src/services/accountRecoveryService.js';

const userId = randomUUID();

beforeAll(async () => {
  await initializeModels();
  await getSequelize().query(
    `INSERT INTO users (id, email, roles, created_at, updated_at)
     VALUES (:id, :email, '{user}', now(), now())`,
    { replacements: { id: userId, email: `recovery-${userId}@example.com` } },
  );
});

afterAll(async () => {
  await getSequelize().close();
});

// The service's where clauses (null checks, IN lists, conditional updates) as Postgres
// evaluates them, rather than as the in-memory double does.
describe('account recovery against Postgres', () => {
  it('opens, refuses early completion, cancels and cascades with the user', async () => {
    const code = await startRecovery(userId, 'email', 'attempt-1');
    const opened = await verifyRecovery(userId, 'attempt-1', code, 3600);

    expect(opened.outcome).toBe('opened');
    expect((await completeRecovery(userId, 'attempt-1')).outcome).toBe('not_ready');

    const resumeCode = await startRecovery(userId, 'email', 'attempt-2');
    expect((await verifyRecovery(userId, 'attempt-2', resumeCode, 3600)).outcome).toBe('resumed');
    expect((await findRecoveryForAttempt(userId, 'attempt-2'))?.state).toBe('pending');

    if (opened.outcome !== 'opened') throw new Error('not opened');
    expect((await cancelRecoveryByToken(opened.cancelToken))?.userId).toBe(userId);
    expect((await findRecoveryForAttempt(userId, 'attempt-2'))?.state).toBe('cancelled');

    await getSequelize().query('DELETE FROM users WHERE id = :id', {
      replacements: { id: userId },
    });
    expect(await AccountRecoveryRequest.count({ where: { userId } })).toBe(0);
  });

  it('completes once the delay has passed and revokes sessions', async () => {
    const owner = randomUUID();
    await getSequelize().query(
      `INSERT INTO users (id, email, roles, created_at, updated_at)
       VALUES (:id, :email, '{user}', now(), now())`,
      { replacements: { id: owner, email: `recovery-${owner}@example.com` } },
    );
    const code = await startRecovery(owner, 'phone', 'attempt-3');
    await verifyRecovery(owner, 'attempt-3', code, 3600);
    await AccountRecoveryRequest.update(
      { completesAt: new Date(Date.now() - 1000) },
      { where: { userId: owner } },
    );

    const result = await completeRecovery(owner, 'attempt-3');

    expect(result.outcome).toBe('completed');
    expect((await findRecoveryForAttempt(owner, 'attempt-3'))?.state).toBe('completed');
  });
});
