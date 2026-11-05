import { Application } from 'express';
import request from 'supertest';
import { beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/services/sessionExchangeService.js', () => ({
  exchangeSubjectToken: vi.fn(),
}));

import { createApp } from '../../../src/app';
import { exchangeSubjectToken } from '../../../src/services/sessionExchangeService.js';

let app: Application;

const body = {
  grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
  subject_token: 'a.b.c',
  subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
};

beforeAll(async () => {
  app = await createApp();
});

describe('POST /sessions/exchange', () => {
  it('answers the session the service issued, and no one may cache it', async () => {
    vi.mocked(exchangeSubjectToken).mockResolvedValue({
      ok: true,
      response: {
        message: 'Success',
        token: 'access',
        refreshToken: 'refresh',
        issued_token_type: 'urn:ietf:params:oauth:token-type:refresh_token',
      },
    });

    const res = await request(app).post('/sessions/exchange').send(body);

    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toMatchObject({ token: 'access', refreshToken: 'refresh' });
  });

  it('tells the client a replay happened', async () => {
    vi.mocked(exchangeSubjectToken).mockResolvedValue({ ok: false, replayed: true });

    const res = await request(app).post('/sessions/exchange').send(body);

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_request', error_description: 'token_already_used' });
  });

  it('answers every other failure with one body', async () => {
    vi.mocked(exchangeSubjectToken).mockResolvedValue({ ok: false, replayed: false });

    const res = await request(app).post('/sessions/exchange').send(body);

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_request' });
  });
});
