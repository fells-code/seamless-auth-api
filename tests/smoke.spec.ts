/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import request from 'supertest';
import app from '../src/app';

describe('GET /health/healthCheck', () => {
  it('returns ok', async () => {
    const res = await request(app).get('/health/status');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'System up' });
  });
});
