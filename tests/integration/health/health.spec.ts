import request from 'supertest';
import { createApp } from '../../../src/app';
import { beforeAll, describe, expect, it } from 'vitest';
import { Application } from 'express';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

describe('Health Routes', () => {
  it('returns system status', async () => {
    const res = await request(app).get('/health/status');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'System up' });
  });

  it('returns 404 for unknown health route', async () => {
    const res = await request(app).get('/health/unknown');

    expect(res.status).toBe(404);
  });
});
