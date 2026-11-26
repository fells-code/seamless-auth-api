import express from 'express';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { holdResponseToFloor, responseFloorMs } from '../../../src/lib/responseFloor.js';

const FLOOR_MS = 120;

function buildApp() {
  const app = express();

  app.get('/ok', holdResponseToFloor, (_req, res) => {
    res.json({ ok: true });
  });
  app.get('/refused', holdResponseToFloor, (_req, res) => {
    res.status(401).json({ error: 'Not allowed' });
  });
  app.get('/empty', holdResponseToFloor, (_req, res) => {
    res.status(204).end();
  });
  app.get('/slow', holdResponseToFloor, async (_req, res) => {
    await new Promise((resolve) => setTimeout(resolve, FLOOR_MS + 30));
    res.json({ ok: true });
  });

  app.get('/fails-after', holdResponseToFloor, async (_req, res, next) => {
    res.set('X-Answer', 'first').status(200).json({ token: 'issued' });
    next(new Error('a write after the answer failed'));
  });
  app.use(
    (
      _error: unknown,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      res.status(500).set('X-Answer', 'second').json({ error: 'Internal Server error' });
    },
  );

  return app;
}

async function time(app: express.Express, path: string) {
  const startedAt = Date.now();
  const res = await request(app).get(path);

  return { elapsed: Date.now() - startedAt, res };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('responseFloorMs', () => {
  it.each([
    [undefined, 250],
    ['0', 0],
    ['400', 400],
    ['-1', 250],
    ['soon', 250],
  ])('reads %s as %d', (value, expected) => {
    vi.stubEnv('LOGIN_RESPONSE_FLOOR_MS', value as string);

    expect(responseFloorMs()).toBe(expected);
  });
});

describe('holdResponseToFloor', () => {
  it.each([
    ['/ok', 200],
    ['/refused', 401],
    ['/empty', 204],
  ])('holds %s to the floor whatever it answers', async (path, status) => {
    vi.stubEnv('LOGIN_RESPONSE_FLOOR_MS', String(FLOOR_MS));

    const { elapsed, res } = await time(buildApp(), path);

    expect(res.status).toBe(status);
    expect(elapsed).toBeGreaterThanOrEqual(FLOOR_MS - 5);
  });

  it('adds nothing to an answer already past the floor', async () => {
    vi.stubEnv('LOGIN_RESPONSE_FLOOR_MS', String(FLOOR_MS));

    const { elapsed, res } = await time(buildApp(), '/slow');

    expect(res.body).toEqual({ ok: true });
    expect(elapsed).toBeLessThan(2 * FLOOR_MS + 30);
  });

  it('can be turned off', async () => {
    vi.stubEnv('LOGIN_RESPONSE_FLOOR_MS', '0');

    const { elapsed } = await time(buildApp(), '/ok');

    expect(elapsed).toBeLessThan(FLOOR_MS);
  });

  it('keeps the first answer when an error follows it during the hold', async () => {
    vi.stubEnv('LOGIN_RESPONSE_FLOOR_MS', String(FLOOR_MS));

    const { res } = await time(buildApp(), '/fails-after');

    expect(res.status).toBe(200);
    expect(res.headers['x-answer']).toBe('first');
    expect(res.headers['content-length']).toBe(String(Buffer.byteLength(res.text)));
    expect(res.body).toEqual({ token: 'issued' });
  });
});
