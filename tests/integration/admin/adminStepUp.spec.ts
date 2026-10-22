import express, { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { loadRoutes } from '../../../src/lib/loadRoutes.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import { registry } from '../../../src/openapi/registry.js';
import { StepUpRequiredErrorSchema } from '../../../src/schemas/stepUp.responses.js';
import { validateBearerToken } from '../../../src/services/sessionService.js';
import { buildFreshStepUpSession, buildSession } from '../../factories/sessionFactory.js';
import { buildUser, testGuid } from '../../factories/userFactory.js';

// Driven through the real bearer and admin checks, which the other admin specs stub out.
vi.unmock('../../../src/middleware/attachAuthMiddleware.js');
vi.unmock('../../../src/middleware/requireAdmin.js');

const GUARDED = [
  'POST /admin/organizations',
  'PATCH /admin/organizations/{organizationId}',
  'DELETE /admin/organizations/{organizationId}',
  'POST /admin/organizations/{organizationId}/members',
  'PATCH /admin/organizations/{organizationId}/members/{userId}',
  'DELETE /admin/organizations/{organizationId}/members/{userId}',
  'PUT /admin/organizations/{organizationId}/oauth-providers/{providerId}/retirement',
  'DELETE /admin/organizations/{organizationId}/oauth-providers/{providerId}/retirement',
  'GET /admin/auth-events/export',
  'POST /admin/users',
  'POST /admin/users/import',
  'DELETE /admin/users',
  'PATCH /admin/users/{userId}',
  'POST /admin/users/{userId}/recovery/device-replacement',
  'DELETE /admin/sessions/by-id/{id}',
  'DELETE /admin/sessions/{userId}/revoke-all',
  'PATCH /system-config/admin',
  'POST /system-config/oauth-providers',
  'PATCH /system-config/oauth-providers/{id}',
  'DELETE /system-config/oauth-providers/{id}',
  'POST /organizations/{organizationId}/members',
];

let app: Application;

function asAdmin(roles = ['admin:read', 'admin:write']) {
  vi.mocked(validateBearerToken).mockResolvedValue({
    user: buildUser({ id: 'user-1', roles }),
    sessionId: 'session-1',
  } as never);
}

function send(route: string) {
  const [method, path] = route.split(' ');
  const url = path.replace(/\{[^}]+\}/g, testGuid);
  const verb = method.toLowerCase() as 'get' | 'post' | 'put' | 'patch' | 'delete';

  return request(app)[verb](url).set('Authorization', 'Bearer token').send({});
}

beforeAll(async () => {
  const { createApp } = await import('../../../src/app.js');

  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  asAdmin();
});

describe('admin writes require a fresh step-up', () => {
  it('documents the step-up 403 on exactly the guarded routes', async () => {
    await loadRoutes(express());

    const documented = new Set<string>();

    for (const definition of registry.definitions) {
      if (definition.type !== 'route') continue;
      const { method, path, responses } = definition.route;
      const forbidden = responses?.['403'] as
        { content?: Record<string, { schema?: unknown }> } | undefined;

      if (forbidden?.content?.['application/json']?.schema === StepUpRequiredErrorSchema) {
        documented.add(`${method.toUpperCase()} ${path}`);
      }
    }

    expect([...documented].sort()).toEqual([...GUARDED].sort());
  });

  it.each(GUARDED)('%s refuses a session that never stepped up', async (route) => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: null, stepUpMethod: null }),
    );

    const res = await send(route);

    expect(res.status).toBe(403);
    expect(res.body).toEqual({
      error: 'step_up_required',
      message: 'Recent step-up authentication is required',
      fresh: false,
      method: null,
      verifiedAt: null,
      expiresAt: null,
      maxAgeSeconds: 300,
    });
  });

  it.each(GUARDED)('%s refuses a step-up older than five minutes', async (route) => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({
        stepUpVerifiedAt: new Date(Date.now() - 6 * 60 * 1000),
        stepUpMethod: 'totp',
      }),
    );

    const res = await send(route);

    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: 'step_up_required', fresh: false, method: 'totp' });
  });

  it.each(GUARDED)('%s lets a fresh step-up through to the handler', async (route) => {
    (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());

    const res = await send(route);

    expect(res.body?.error).not.toBe('step_up_required');
    expect(res.status).not.toBe(403);
  });

  it('checks the admin role before the step-up', async () => {
    asAdmin(['admin:read']);

    const res = await send('PATCH /admin/users/{userId}');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'Forbidden' });
    expect(Session.findOne).not.toHaveBeenCalled();
  });

  it('applies a role change once the session has stepped up', async () => {
    const target = buildUser({ id: testGuid, roles: ['user'] });
    (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
    (User.findByPk as any).mockResolvedValue(target);
    (User.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch(`/admin/users/${testGuid}`)
      .set('Authorization', 'Bearer token')
      .send({ roles: ['user'] });

    expect(res.status).toBe(200);
    expect(target.update).toHaveBeenCalled();
  });

  it('leaves admin reads open without a step-up', async () => {
    (Session.findOne as any).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: null, stepUpMethod: null }),
    );
    (User.findAll as any).mockResolvedValue([]);
    (User.count as any).mockResolvedValue(0);

    const res = await request(app).get('/admin/users').set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
  });
});
