import { Application } from 'express';
import { ForeignKeyConstraintError, UniqueConstraintError } from 'sequelize';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Permission } from '../../../src/models/permissions.js';
import { RolePermission } from '../../../src/models/rolePermissions.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { buildFreshStepUpSession, buildSession } from '../../factories/sessionFactory';

let app: Application;

const now = new Date('2026-11-05T12:00:00.000Z');

function buildPermission(overrides: Partial<any> = {}) {
  return {
    id: '4e1f2a3b-5c6d-4e7f-8a9b-0c1d2e3f4a5b',
    name: 'invoices:read',
    description: null,
    createdAt: now,
    updatedAt: now,
    update: vi.fn().mockImplementation(function update(this: any, values: any) {
      Object.assign(this, values);
      return Promise.resolve(this);
    }),
    destroy: vi.fn(),
    ...overrides,
  };
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
  (getSystemConfig as any).mockResolvedValue({
    access_token_ttl: '15m',
    available_roles: ['user', 'admin:write', 'finance'],
  });
  (Permission.findAll as any).mockResolvedValue([]);
  (RolePermission.findAll as any).mockResolvedValue([]);
});

describe('permission catalogue', () => {
  it('lists permissions', async () => {
    (Permission.findAll as any).mockResolvedValue([buildPermission()]);

    const res = await request(app).get('/admin/permissions');

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.permissions[0].name).toBe('invoices:read');
  });

  it('creates a permission and audits it', async () => {
    (Permission.create as any).mockResolvedValue(buildPermission());

    const res = await request(app).post('/admin/permissions').send({ name: 'invoices:read' });

    expect(res.status).toBe(201);
    expect(res.body.permission.name).toBe('invoices:read');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'admin_permission_created',
        metadata: { permission: 'invoices:read' },
      }),
    );
  });

  it('needs a fresh step-up to create', async () => {
    (Session.findOne as any).mockResolvedValue(buildSession());

    const res = await request(app).post('/admin/permissions').send({ name: 'invoices:read' });

    expect(res.status).toBe(403);
    expect(Permission.create).not.toHaveBeenCalled();
  });

  // A wildcard would read as a grant that exact matching never honors.
  it('refuses a wildcard name', async () => {
    const res = await request(app).post('/admin/permissions').send({ name: 'invoices:*' });

    expect(res.status).toBe(400);
    expect(Permission.create).not.toHaveBeenCalled();
  });

  it('answers 409 for a name already taken', async () => {
    (Permission.create as any).mockRejectedValue(new UniqueConstraintError({}));

    const res = await request(app).post('/admin/permissions').send({ name: 'invoices:read' });

    expect(res.status).toBe(409);
  });

  it('updates a description', async () => {
    (Permission.findOne as any).mockResolvedValue(buildPermission());

    const res = await request(app)
      .patch('/admin/permissions/invoices:read')
      .send({ description: 'Read invoices' });

    expect(res.status).toBe(200);
    expect(res.body.permission.description).toBe('Read invoices');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'admin_permission_updated' }),
    );
  });

  it('answers 404 updating a permission that does not exist', async () => {
    (Permission.findOne as any).mockResolvedValue(null);

    const res = await request(app)
      .patch('/admin/permissions/invoices:read')
      .send({ description: null });

    expect(res.status).toBe(404);
  });

  it('deletes a permission no role grants', async () => {
    const permission = buildPermission();
    (Permission.findOne as any).mockResolvedValue(permission);

    const res = await request(app).delete('/admin/permissions/invoices:read');

    expect(res.status).toBe(200);
    expect(permission.destroy).toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'admin_permission_deleted' }),
    );
  });

  it('refuses to delete a permission a role grants, and names the role', async () => {
    const permission = buildPermission();
    (Permission.findOne as any).mockResolvedValue(permission);
    (RolePermission.findAll as any).mockResolvedValue([
      { roleKind: 'instance', roleName: 'finance' },
    ]);

    const res = await request(app).delete('/admin/permissions/invoices:read');

    expect(res.status).toBe(409);
    expect(res.body.details.roles).toEqual([{ kind: 'instance', name: 'finance' }]);
    expect(permission.destroy).not.toHaveBeenCalled();
  });

  it('answers 409 when a mapping lands between the check and the delete', async () => {
    (Permission.findOne as any).mockResolvedValue(
      buildPermission({
        destroy: vi.fn().mockRejectedValue(new ForeignKeyConstraintError({} as any)),
      }),
    );

    const res = await request(app).delete('/admin/permissions/invoices:read');

    expect(res.status).toBe(409);
  });

  it('answers 404 deleting a permission that does not exist', async () => {
    (Permission.findOne as any).mockResolvedValue(null);

    const res = await request(app).delete('/admin/permissions/invoices:read');

    expect(res.status).toBe(404);
  });
});

describe('role mappings', () => {
  it('lists instance roles with what they grant', async () => {
    (RolePermission.findAll as any).mockResolvedValue([
      { roleName: 'finance', permissionName: 'invoices:read' },
      { roleName: 'finance', permissionName: 'invoices:write' },
    ]);

    const res = await request(app).get('/admin/roles');

    expect(res.status).toBe(200);
    expect(res.body.roles).toContainEqual({
      name: 'finance',
      kind: 'instance',
      description: null,
      builtIn: false,
      permissions: ['invoices:read', 'invoices:write'],
    });
    expect(res.body.roles).toContainEqual(
      expect.objectContaining({ name: 'user', permissions: [] }),
    );
  });

  it('replaces a mapping and audits what changed', async () => {
    (Permission.findAll as any).mockResolvedValue([
      { name: 'invoices:read' },
      { name: 'reports:read' },
    ]);
    (RolePermission.findAll as any)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ permissionName: 'invoices:read' }, { permissionName: 'old:read' }]);

    const res = await request(app)
      .put('/admin/roles/instance/finance/permissions')
      .send({ permissions: ['reports:read', 'invoices:read', 'reports:read'] });

    expect(res.status).toBe(200);
    expect(res.body.role.permissions).toEqual(['invoices:read', 'reports:read']);
    expect(RolePermission.destroy).toHaveBeenCalled();
    expect(RolePermission.bulkCreate).toHaveBeenCalledWith(
      [
        expect.objectContaining({ roleName: 'finance', permissionName: 'invoices:read' }),
        expect.objectContaining({ roleName: 'finance', permissionName: 'reports:read' }),
      ],
      expect.anything(),
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'admin_role_permissions_updated',
        metadata: {
          kind: 'instance',
          role: 'finance',
          added: ['reports:read'],
          removed: ['old:read'],
        },
      }),
    );
  });

  it('needs a fresh step-up to change a mapping', async () => {
    (Session.findOne as any).mockResolvedValue(buildSession());

    const res = await request(app)
      .put('/admin/roles/instance/finance/permissions')
      .send({ permissions: [] });

    expect(res.status).toBe(403);
    expect(RolePermission.bulkCreate).not.toHaveBeenCalled();
  });

  it('answers 404 for a role the instance does not offer', async () => {
    const res = await request(app)
      .put('/admin/roles/instance/ghost/permissions')
      .send({ permissions: [] });

    expect(res.status).toBe(404);
    expect(RolePermission.bulkCreate).not.toHaveBeenCalled();
  });

  it('refuses a permission the catalogue does not hold, and names it', async () => {
    const res = await request(app)
      .put('/admin/roles/instance/finance/permissions')
      .send({ permissions: ['ghost:read'] });

    expect(res.status).toBe(400);
    expect(res.body.details.permissions).toEqual(['ghost:read']);
    expect(RolePermission.bulkCreate).not.toHaveBeenCalled();
  });
});

describe('GET /users/me/permissions', () => {
  it('answers with what the caller holds now', async () => {
    (RolePermission.findAll as any).mockResolvedValue([{ permissionName: 'invoices:read' }]);

    const res = await request(app).get('/users/me/permissions');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      roles: ['user'],
      permissions: ['invoices:read'],
      organizationId: null,
      organizationRoles: [],
      organizationPermissions: [],
    });
  });
});
