import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { SystemConfig } from '../../../src/models/systemConfig.js';
import { User } from '../../../src/models/users.js';
import {
  getSystemConfig,
  invalidateSystemConfigCache,
} from '../../../src/config/getSystemConfig.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();

  (getSystemConfig as any).mockResolvedValue({
    available_roles: ['user', 'admin'],
    default_roles: ['user'],
  });
});

describe('GET /system-config/roles', () => {
  it('returns available roles', async () => {
    const res = await request(app).get('/system-config/roles');

    expect(res.status).toBe(200);
    expect(res.body.roles).toEqual(['user', 'admin']);
  });
});

describe('GET /system-config/admin', () => {
  it('returns system config', async () => {
    const config = buildSystemConfig();

    (SystemConfig.findAll as any).mockResolvedValue(
      Object.entries(config).map(([key, value]) => ({
        key,
        value,
      })),
    );

    const res = await request(app).get('/system-config/admin');

    expect(res.status).toBe(200);
    expect(res.body.app_name).toBe('SeamlessAuth');
    expect(res.body.available_roles).toEqual(['user', 'admin']);
  });

  it('returns 500 when schema invalid', async () => {
    (SystemConfig.findAll as any).mockResolvedValue([{ key: 'app_name', value: 'SeamlessAuth' }]);

    const res = await request(app).get('/system-config/admin');

    expect(res.status).toBe(500);
  });
});

describe('PATCH /system-config/admin', () => {
  it('updates system config', async () => {
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
  });

  it('accepts scoped role names', async () => {
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin:read', 'admin:write'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('rejects invalid payload', async () => {
    const res = await request(app).patch('/system-config/admin').send({ invalid: true });

    expect(res.status).toBe(400);
  });

  it('rejects removing role in use', async () => {
    (User.findAll as any).mockResolvedValue([{ roles: ['admin'] }]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Role removal blocked');
  });

  it('rejects empty update', async () => {
    const res = await request(app).patch('/system-config/admin').send({});

    expect(res.status).toBe(400);
  });
});
