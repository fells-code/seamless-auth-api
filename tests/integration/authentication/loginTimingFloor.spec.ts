import { Application } from 'express';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { signEphemeralToken } from '../../../src/lib/token.js';
import { Credential } from '../../../src/models/credentials.js';
import { User } from '../../../src/models/users.js';
import { buildUser } from '../../factories/userFactory';

/**
 * Identical bodies that arrive at measurably different times still answer the question.
 * The real path reads the users table, the lockout counter, the credentials table and
 * the login policy; the decoy path reads only the policy. The floor removes that
 * difference by holding every answer to the same minimum.
 *
 * The floor is off for the rest of the suite so that it is not paid for by every login
 * test, which is why it is turned on here rather than assumed.
 */

const FLOOR_MS = 150;

let app: Application;

beforeAll(async () => {
  process.env.LOGIN_RESPONSE_FLOOR_MS = String(FLOOR_MS);
  app = await createApp();
});

afterAll(() => {
  process.env.LOGIN_RESPONSE_FLOOR_MS = '0';
});

beforeEach(() => {
  vi.clearAllMocks();
  (signEphemeralToken as any).mockResolvedValue('token');
  (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });
});

async function timeLogin(identifier: string) {
  const startedAt = Date.now();

  const res = await request(app).post('/login').send({ identifier });

  return { elapsed: Date.now() - startedAt, status: res.status };
}

describe('POST /login timing floor', () => {
  it('holds an unknown identifier to the floor', async () => {
    (User.findOne as any).mockResolvedValue(null);

    const { elapsed, status } = await timeLogin('nobody@example.com');

    expect(status).toBe(200);
    expect(elapsed).toBeGreaterThanOrEqual(FLOOR_MS);
  });

  it('holds a real account to the same floor', async () => {
    (User.findOne as any).mockResolvedValue(buildUser({ verified: true }));
    (Credential.findOne as any).mockResolvedValue({});

    const { elapsed, status } = await timeLogin('real@example.com');

    expect(status).toBe(200);
    expect(elapsed).toBeGreaterThanOrEqual(FLOOR_MS);
  });

  it('can be turned off', async () => {
    process.env.LOGIN_RESPONSE_FLOOR_MS = '0';
    (User.findOne as any).mockResolvedValue(null);

    const { elapsed } = await timeLogin('nobody@example.com');

    process.env.LOGIN_RESPONSE_FLOOR_MS = String(FLOOR_MS);

    expect(elapsed).toBeLessThan(FLOOR_MS);
  });
});
