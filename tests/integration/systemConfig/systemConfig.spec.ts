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
    expect(SystemConfig.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ updatedBy: 'user-1' }),
      expect.anything(),
    );
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

  it('handles a null user list when computing roles in use', async () => {
    (User.findAll as any).mockResolvedValue(null);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('returns 400 when the payload fails the dynamic (config-aware) schema', async () => {
    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['admin'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid system config payload');
  });

  it('allows keeping a role that is still available and in use', async () => {
    (User.findAll as any).mockResolvedValue([{ roles: ['user'] }]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('tolerates users without any roles when computing roles in use', async () => {
    (User.findAll as any).mockResolvedValue([{ roles: null }]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
  });
});

describe('GET /system-config/roles (additional branches)', () => {
  it('returns an empty roles list when none are configured', async () => {
    (getSystemConfig as any).mockResolvedValue({
      available_roles: undefined,
      default_roles: ['user'],
    });

    const res = await request(app).get('/system-config/roles');

    expect(res.status).toBe(200);
    expect(res.body.roles).toEqual([]);
  });
});

describe('GET /system-config/public', () => {
  it('returns the configured login methods', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey', 'phone_otp'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).get('/system-config/public');

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey', 'phone_otp']);
  });

  // A client with no methods has nothing to render, so a config that never had
  // login_methods written answers with the defaults rather than an empty list.
  it('falls back to the defaults when the stored config has no login methods', async () => {
    const res = await request(app).get('/system-config/public');

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey', 'magic_link']);
  });

  it('exposes nothing but the login methods', async () => {
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig());

    const res = await request(app).get('/system-config/public');

    expect(res.status).toBe(200);
    expect(Object.keys(res.body)).toEqual(['loginMethods']);
  });
});
