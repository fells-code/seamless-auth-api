import { randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { getSequelize, initializeModels } from '../../src/models/index.js';
import { revokeAllSessionsForUsers } from '../../src/services/sessionRevocation.js';
import { claimSessionRotation, validateSessionRecord } from '../../src/services/sessionService.js';

type Models = Awaited<ReturnType<typeof initializeModels>>;

let Session: Models['Session'];
let User: Models['User'];

async function createUser() {
  const id = randomUUID();
  await User.create({ id, email: `revoke-${id}@example.com`, phone: null });
  return id;
}

function createSession(userId: string) {
  const now = Date.now();
  return Session.create({
    userId,
    mode: 'server',
    refreshTokenLookup: randomUUID(),
    expiresAt: new Date(now + 3_600_000),
    idleExpiresAt: new Date(now + 3_600_000),
    lastUsedAt: new Date(now),
  });
}

beforeAll(async () => {
  ({ Session, User } = await initializeModels());
});

afterAll(async () => {
  await getSequelize().close();
});

describe('revoking every session for a user', () => {
  it('revokes every live row in one update and records the cutoff', async () => {
    const userId = await createUser();
    const other = await createUser();
    const sessions = await Promise.all([createSession(userId), createSession(userId)]);
    const untouched = await createSession(other);

    const revoked = await revokeAllSessionsForUsers(userId, 'user_logout_all');

    expect(revoked).toBe(2);
    for (const session of sessions) {
      await session.reload();
      expect(session.revokedReason).toBe('user_logout_all');
    }
    await untouched.reload();
    expect(untouched.revokedAt).toBeNull();

    const user = await User.findByPk(userId);
    expect(user?.sessionsRevokedBefore).toBeInstanceOf(Date);
  });

  it('refuses a session the update missed and accepts one started afterwards', async () => {
    const userId = await createUser();
    const missed = await createSession(userId);

    await revokeAllSessionsForUsers(userId, 'user_logout_all');
    // Stands in for a row a refresh wrote while the revoke ran, which the update never saw.
    await Session.update({ revokedAt: null, revokedReason: null }, { where: { id: missed.id } });

    expect(await validateSessionRecord(missed.id)).toBeNull();

    await new Promise((resolve) => setTimeout(resolve, 5));
    const later = await createSession(userId);
    expect(await validateSessionRecord(later.id)).not.toBeNull();
  });

  it('leaves a rotation that races the revoke unable to claim its session', async () => {
    const userId = await createUser();
    const current = await createSession(userId);

    const [replacement] = await Promise.all([
      createSession(userId),
      revokeAllSessionsForUsers(userId, 'user_logout_all'),
    ]);
    const claimed = await claimSessionRotation(current, replacement.id);

    expect(claimed).toBe(false);
    expect(await validateSessionRecord(current.id)).toBeNull();
  });
});
