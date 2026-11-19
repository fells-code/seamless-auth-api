import { randomUUID } from 'crypto';
import fs from 'fs';
import { decodeJwt } from 'jose';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { Session } from '../../src/models/sessions.js';
import { SystemConfig } from '../../src/models/systemConfig.js';
import { User } from '../../src/models/users.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

type App = Awaited<ReturnType<typeof import('../../src/app.js').createApp>>;
type Issuance = typeof import('../../src/services/sessionIssuance.js');

const EMAIL_DOMAIN = 'refresh-rotation.test';

let app: App;
let issuance: Issuance;
const savedEnv: Record<string, string | undefined> = {};

function setEnv(values: Record<string, string>) {
  for (const [key, value] of Object.entries(values)) {
    savedEnv[key] = process.env[key];
    process.env[key] = value;
  }
}

beforeAll(async () => {
  setEnv({
    ISSUER: 'http://localhost:5312',
    DISABLE_AUTH_RATE_LIMITS: 'true',
    SEAMLESS_DEV_KEYS_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'seamless-keys-')),
  });

  await initializeModels();

  for (const [key, value] of Object.entries(buildSystemConfig())) {
    await getSequelize().query(
      `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
       VALUES (:key, CAST(:value AS jsonb), now(), now())
       ON CONFLICT (key) DO NOTHING`,
      { replacements: { key, value: JSON.stringify(value) } },
    );
  }
  await getSequelize().query(
    `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
     VALUES ('max_concurrent_sessions', 'null'::jsonb, now(), now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
  );
  invalidateSystemConfigCache();

  issuance = await import('../../src/services/sessionIssuance.js');

  const { initDevSigningKey } = await import('../../src/utils/signingKeyStore.js');
  const { createApp } = await import('../../src/app.js');
  initDevSigningKey();
  app = await createApp();
});

beforeEach(() => {
  invalidateSystemConfigCache();
});

afterAll(async () => {
  await SystemConfig.destroy({ where: { key: ['max_concurrent_sessions'] } });
  await getSequelize().query(`DELETE FROM users WHERE email LIKE :pattern`, {
    replacements: { pattern: `%@${EMAIL_DOMAIN}` },
  });
  invalidateSystemConfigCache();
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  await getSequelize().close();
});

function fakeResponse() {
  const res: any = { body: undefined, statusCode: 200 };
  res.status = (code: number) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body: unknown) => {
    res.body = body;
    return res;
  };
  return res;
}

async function signIn(roles = ['user']) {
  const user = await User.create({
    email: `${randomUUID()}@${EMAIL_DOMAIN}`,
    phone: null,
    roles,
  } as never);
  const res = fakeResponse();

  await issuance.issueSessionAndRespond({
    method: 'passkey',
    user: { id: user.id, email: user.email, phone: null, roles },
    req: {
      ip: '127.0.0.1',
      headers: { 'user-agent': 'refresh-rotation-test' },
      get: () => 'refresh-rotation-test',
    } as never,
    res,
  });

  return {
    user,
    sessionId: decodeJwt(res.body.token).sid as string,
    refreshToken: res.body.refreshToken as string,
    token: res.body.token as string,
  };
}

function refresh(refreshToken: string) {
  return request(app).post('/refresh').set('Authorization', `Bearer ${refreshToken}`);
}

async function liveSessions(userId: string) {
  const rows = await Session.findAll({ where: { userId, revokedAt: null } });
  return rows.filter((row) => row.replacedBySessionId === null);
}

async function ageRotation(sessionId: string, ms: number) {
  await Session.update({ rotatedAt: new Date(Date.now() - ms) }, { where: { id: sessionId } });
}

describe('the refresh replay window (#598)', () => {
  it('answers two concurrent refreshes of one token with the same successor', async () => {
    const { user, refreshToken, sessionId } = await signIn();

    const [first, second] = await Promise.all([refresh(refreshToken), refresh(refreshToken)]);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(second.body.refreshToken).toBe(first.body.refreshToken);
    expect(second.body.sessionId).toBe(first.body.sessionId);
    expect(first.body.sessionId).not.toBe(sessionId);

    // One chain, not two: whatever the race created besides the successor is revoked.
    const live = await liveSessions(user.id);
    expect(live.map((row) => row.id)).toEqual([first.body.sessionId]);

    const next = await refresh(first.body.refreshToken);
    expect(next.status).toBe(200);
  });

  it('answers a sequential replay in the window, a bounded number of times', async () => {
    const { user, refreshToken } = await signIn();

    const rotated = await refresh(refreshToken);
    expect(rotated.status).toBe(200);

    for (let replay = 0; replay < 3; replay += 1) {
      const again = await refresh(refreshToken);
      expect(again.status).toBe(200);
      expect(again.body.refreshToken).toBe(rotated.body.refreshToken);
    }

    const spent = await refresh(refreshToken);
    expect(spent.status).toBe(401);
    expect(spent.body.error).toBe('refresh_token_reused');
    expect(await liveSessions(user.id)).toEqual([]);
  });

  it('treats the predecessor as reuse once the window has passed', async () => {
    const { user, refreshToken, sessionId } = await signIn();

    const rotated = await refresh(refreshToken);
    await ageRotation(sessionId, 6_000);

    const late = await refresh(refreshToken);

    expect(late.status).toBe(401);
    expect(late.body.error).toBe('refresh_token_reused');
    expect(await liveSessions(user.id)).toEqual([]);
    expect((await refresh(rotated.body.refreshToken)).status).toBe(401);

    const predecessor = await Session.findByPk(sessionId);
    expect(predecessor?.replayTokenCiphertext).toBeNull();
  });

  it('treats an older ancestor as reuse even inside the window', async () => {
    const { user, refreshToken } = await signIn();

    const second = await refresh(refreshToken);
    const third = await refresh(second.body.refreshToken);
    expect(third.status).toBe(200);

    const ancestor = await refresh(refreshToken);

    expect(ancestor.status).toBe(401);
    expect(ancestor.body.error).toBe('refresh_token_reused');
    expect(await liveSessions(user.id)).toEqual([]);
  });

  it('stores the successor token only sealed', async () => {
    const { refreshToken, sessionId } = await signIn();

    const rotated = await refresh(refreshToken);
    const predecessor = await Session.findByPk(sessionId);

    expect(predecessor?.replayTokenCiphertext).toMatch(/^v1\./);
    expect(predecessor?.replayTokenCiphertext).not.toContain(rotated.body.refreshToken);
  });
});

describe('reuse detection after the idle window (#593)', () => {
  it('revokes the chain when a rotated token returns after its row idled out', async () => {
    const { user, refreshToken, sessionId } = await signIn();

    const rotated = await refresh(refreshToken);
    await Session.update(
      {
        idleExpiresAt: new Date(Date.now() - 1_000),
        rotatedAt: new Date(Date.now() - 9 * 3_600_000),
      },
      { where: { id: sessionId } },
    );

    const reused = await refresh(refreshToken);

    expect(reused.status).toBe(401);
    expect(reused.body.error).toBe('refresh_token_reused');
    expect(await liveSessions(user.id)).toEqual([]);
    expect((await refresh(rotated.body.refreshToken)).status).toBe(401);
  });
});

describe('revoking a session that has rotated since it was listed (#592)', () => {
  it('ends the head of the chain for the user', async () => {
    const { user, refreshToken, sessionId } = await signIn();
    const other = await signIn();
    const rotated = await refresh(refreshToken);

    const res = await request(app)
      .delete(`/sessions/${sessionId}`)
      .set('Authorization', `Bearer ${other.token}`);
    // Another user's row is not theirs to revoke.
    expect(res.status).toBe(404);

    const own = await request(app)
      .delete(`/sessions/${sessionId}`)
      .set('Authorization', `Bearer ${rotated.body.token}`);

    expect(own.status).toBe(200);
    expect(await liveSessions(user.id)).toEqual([]);
    const head = await Session.findByPk(rotated.body.sessionId);
    expect(head?.revokedReason).toBe('user_revoked');
    expect((await refresh(rotated.body.refreshToken)).status).toBe(401);
  });

  it('ends the head of the chain for an admin', async () => {
    const admin = await signIn(['admin']);
    await Session.update(
      { stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' },
      { where: { id: admin.sessionId } },
    );
    const target = await signIn();
    const rotated = await refresh(target.refreshToken);

    const res = await request(app)
      .delete(`/admin/sessions/by-id/${target.sessionId}`)
      .set('Authorization', `Bearer ${admin.token}`);

    expect(res.status).toBe(200);
    expect(await liveSessions(target.user.id)).toEqual([]);
    const head = await Session.findByPk(rotated.body.sessionId);
    expect(head?.revokedReason).toBe('admin_revoke');
  });
});
