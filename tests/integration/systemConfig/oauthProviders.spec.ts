import request from 'supertest';
import { Application } from 'express';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  getSystemConfig,
  invalidateSystemConfigCache,
} from '../../../src/config/getSystemConfig.js';
import { SystemConfig } from '../../../src/models/systemConfig.js';
import { createApp } from '../../../src/app';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

let app: Application;

function buildProvider(overrides: Record<string, unknown> = {}) {
  return {
    id: 'google',
    name: 'Google',
    enabled: true,
    clientId: 'google-client-id',
    clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: ['openid', 'email'],
    redirectUris: [],
    subjectJsonPath: 'sub',
    emailJsonPath: 'email',
    emailVerifiedJsonPath: 'email_verified',
    allowSignup: true,
    accountLinking: 'email',
    requireEmailVerified: false,
    ...overrides,
  };
}

function mockConfigWithProviders(providers: Array<Record<string, unknown>>) {
  (getSystemConfig as any).mockResolvedValue(buildSystemConfig({ oauth_providers: providers }));
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (SystemConfig.upsert as any).mockResolvedValue(undefined);
});

describe('GET /system-config/oauth-providers', () => {
  it('returns the configured providers', async () => {
    mockConfigWithProviders([buildProvider()]);

    const res = await request(app).get('/system-config/oauth-providers');

    expect(res.status).toBe(200);
    expect(res.body.providers).toHaveLength(1);
    expect(res.body.providers[0].id).toBe('google');
    expect(res.body.providers[0].clientSecretEnv).toBe('GOOGLE_CLIENT_SECRET');
  });

  it('returns an empty list when none are configured', async () => {
    mockConfigWithProviders([]);

    const res = await request(app).get('/system-config/oauth-providers');

    expect(res.status).toBe(200);
    expect(res.body.providers).toEqual([]);
  });
});

describe('POST /system-config/oauth-providers', () => {
  it('adds a new provider', async () => {
    mockConfigWithProviders([]);

    const res = await request(app)
      .post('/system-config/oauth-providers')
      .send(buildProvider({ id: 'github', name: 'GitHub' }));

    expect(res.status).toBe(201);
    expect(res.body.provider.id).toBe('github');
    expect(SystemConfig.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ key: 'oauth_providers' }),
      expect.anything(),
    );
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
  });

  it('rejects a duplicate provider id with 409', async () => {
    mockConfigWithProviders([buildProvider()]);

    const res = await request(app).post('/system-config/oauth-providers').send(buildProvider());

    expect(res.status).toBe(409);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('rejects an invalid payload with 400', async () => {
    mockConfigWithProviders([]);

    const res = await request(app)
      .post('/system-config/oauth-providers')
      .send({ id: 'broken', name: 'Broken' });

    expect(res.status).toBe(400);
  });

  it('never accepts a raw client secret field', async () => {
    mockConfigWithProviders([]);

    const res = await request(app)
      .post('/system-config/oauth-providers')
      .send(buildProvider({ id: 'okta', clientSecret: 'super-secret-value' }));

    expect(res.status).toBe(201);
    expect(res.body.provider).not.toHaveProperty('clientSecret');
  });
});

describe('PATCH /system-config/oauth-providers/:id', () => {
  it('updates an existing provider', async () => {
    mockConfigWithProviders([buildProvider()]);

    const res = await request(app)
      .patch('/system-config/oauth-providers/google')
      .send({ enabled: false, name: 'Google Workspace' });

    expect(res.status).toBe(200);
    expect(res.body.provider.enabled).toBe(false);
    expect(res.body.provider.name).toBe('Google Workspace');
    expect(res.body.provider.id).toBe('google');
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
  });

  it('returns 404 for an unknown provider', async () => {
    mockConfigWithProviders([buildProvider()]);

    const res = await request(app)
      .patch('/system-config/oauth-providers/missing')
      .send({ enabled: false });

    expect(res.status).toBe(404);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('rejects attempts to change the id via the body', async () => {
    mockConfigWithProviders([buildProvider()]);

    const res = await request(app)
      .patch('/system-config/oauth-providers/google')
      .send({ id: 'renamed' });

    expect(res.status).toBe(400);
  });
});

describe('DELETE /system-config/oauth-providers/:id', () => {
  it('removes an existing provider', async () => {
    mockConfigWithProviders([buildProvider(), buildProvider({ id: 'github', name: 'GitHub' })]);

    const res = await request(app).delete('/system-config/oauth-providers/google');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, id: 'google' });
    expect(SystemConfig.upsert).toHaveBeenCalled();
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
  });

  it('returns 404 when deleting an unknown provider', async () => {
    mockConfigWithProviders([buildProvider()]);

    const res = await request(app).delete('/system-config/oauth-providers/missing');

    expect(res.status).toBe(404);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });
});
