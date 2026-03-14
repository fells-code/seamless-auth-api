/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import request from 'supertest';
import { createApp } from '../src/app.js';
import { Application } from 'express';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

describe('GET /health/status', () => {
  it('returns ok', async () => {
    const res = await request(app).get('/health/status');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'System up' });
  });
});
