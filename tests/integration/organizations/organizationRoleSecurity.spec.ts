import { Application } from 'express';
import { Op } from 'sequelize';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { OrganizationMembership } from '../../../src/models/organizationMemberships.js';
import { OrganizationRole } from '../../../src/models/organizationRoles.js';
import { Organization } from '../../../src/models/organizations.js';
import { RolePermission } from '../../../src/models/rolePermissions.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  buildOrganization,
  buildOrganizationMembership,
  testOrganizationId,
} from '../../factories/organizationFactory';
import { buildFreshStepUpSession, buildSession } from '../../factories/sessionFactory';
import { buildUser } from '../../factories/userFactory';

const memberId = 'a1863941-552c-428a-aecd-599814979e8d';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

function mappings(byRole: Record<string, string[]>) {
  (RolePermission.findAll as any).mockImplementation(async ({ where }: any) =>
    where.roleName[Op.in].flatMap((role: string) =>
      (byRole[role] ?? []).map((permissionName) => ({ permissionName })),
    ),
  );
}

function mockMemberships(caller: string[], target: string[] = ['member']) {
  (Organization.findByPk as any).mockResolvedValue(buildOrganization());
  (OrganizationMembership.findOne as any).mockImplementation(async ({ where }: any) =>
    where.userId === 'user-1'
      ? buildOrganizationMembership({ roles: caller })
      : buildOrganizationMembership({ userId: memberId, roles: target }),
  );
  (OrganizationMembership.findAll as any).mockResolvedValue([
    buildOrganizationMembership({ roles: ['owner'] }),
    buildOrganizationMembership({ userId: memberId, roles: target }),
  ]);
  (User.findByPk as any).mockResolvedValue(buildUser({ id: memberId }));
}

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
  (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });
  (RolePermission.findAll as any).mockResolvedValue([]);
  (OrganizationRole.findAll as any).mockImplementation(async ({ where }: any) =>
    where.name[Op.in].map((name: string) => ({ name })),
  );
});

describe('who can grant organization roles', () => {
  it('refuses an organization admin granting owner to someone else', async () => {
    mockMemberships(['admin']);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['owner'] });

    expect(res.status).toBe(403);
    expect(res.body.details.roles).toEqual(['owner']);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'organization_member_role_grant_refused',
        userId: memberId,
      }),
    );
  });

  it('refuses an organization admin taking owner away', async () => {
    mockMemberships(['admin'], ['owner', 'admin']);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['admin'] });

    expect(res.status).toBe(403);
  });

  it('refuses an organization admin removing an owner', async () => {
    const target = buildOrganizationMembership({ userId: memberId, roles: ['owner'] });
    mockMemberships(['admin'], ['owner']);
    (OrganizationMembership.findOne as any).mockImplementation(async ({ where }: any) =>
      where.userId === 'user-1' ? buildOrganizationMembership({ roles: ['admin'] }) : target,
    );

    const res = await request(app).delete(
      `/organizations/${testOrganizationId}/members/${memberId}`,
    );

    expect(res.status).toBe(403);
    expect(target.destroy).not.toHaveBeenCalled();
  });

  it('lets an owner grant owner', async () => {
    mockMemberships(['owner']);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['owner'] });

    expect(res.status).toBe(200);
  });

  it('refuses a role carrying a permission the manager does not hold', async () => {
    mockMemberships(['admin']);
    mappings({ admin: ['projects:write'], finance: ['payments:approve'] });

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['finance'] });

    expect(res.status).toBe(403);
    expect(res.body.details.roles).toEqual(['finance']);
  });

  it('allows a role whose permissions the manager holds', async () => {
    mockMemberships(['admin']);
    mappings({ admin: ['projects:write', 'projects:read'], viewer: ['projects:read'] });

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['viewer'] });

    expect(res.status).toBe(200);
  });

  it('lets a manager take away a role they could not grant', async () => {
    mockMemberships(['admin'], ['finance', 'member']);
    mappings({ admin: [], finance: ['payments:approve'] });

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['member'] });

    expect(res.status).toBe(200);
  });

  it('exempts an owner from holding the permissions, which depend on the mapping', async () => {
    mockMemberships(['owner']);
    mappings({ finance: ['payments:approve'] });

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['finance'] });

    expect(res.status).toBe(200);
  });

  it('needs a fresh step-up', async () => {
    mockMemberships(['owner']);
    (Session.findOne as any).mockResolvedValue(buildSession());

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['member'] });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('step_up_required');
  });

  it('refuses a role outside the catalogue, and names it', async () => {
    mockMemberships(['owner']);
    (OrganizationRole.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['ghost'] });

    expect(res.status).toBe(400);
    expect(res.body.details.roles).toEqual(['ghost']);
  });

  it('lets a member keep a legacy role the catalogue no longer lists', async () => {
    mockMemberships(['owner'], ['Team Lead']);
    (OrganizationRole.findAll as any).mockResolvedValue([{ name: 'member' }]);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['Team Lead', 'member'] });

    expect(res.status).toBe(200);
  });
});

describe('organization membership audit', () => {
  it('records what a role change added and removed', async () => {
    mockMemberships(['owner'], ['member']);

    await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ roles: ['admin'] });

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'organization_member_updated',
        actorUserId: 'user-1',
        userId: memberId,
        metadata: {
          organizationId: testOrganizationId,
          roles: ['admin'],
          rolesAdded: ['admin'],
          rolesRemoved: ['member'],
        },
      }),
    );
  });

  it('records a scope change', async () => {
    mockMemberships(['owner'], ['member']);

    await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${memberId}`)
      .send({ scopes: ['members:read'] });

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'organization_member_updated',
        metadata: expect.objectContaining({ scopes: ['members:read'] }),
      }),
    );
  });

  it('records a removal', async () => {
    mockMemberships(['owner'], ['member']);

    const res = await request(app).delete(
      `/organizations/${testOrganizationId}/members/${memberId}`,
    );

    expect(res.status).toBe(200);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'organization_member_removed',
        userId: memberId,
        metadata: { organizationId: testOrganizationId, roles: ['member'] },
      }),
    );
  });
});
