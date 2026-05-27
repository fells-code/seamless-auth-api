import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { Organization } from '../../../src/models/organizations.js';
import { OrganizationMembership } from '../../../src/models/organizationMemberships.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import {
  buildOrganization,
  buildOrganizationMembership,
  testOrganizationId,
} from '../../factories/organizationFactory';
import { buildSession } from '../../factories/sessionFactory';
import { buildUser } from '../../factories/userFactory';
import { signAccessToken } from '../../../src/lib/token.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('organizations', () => {
  it('lists organizations for the authenticated user', async () => {
    (OrganizationMembership.findAll as any).mockResolvedValue([buildOrganizationMembership()]);
    (Organization.findAll as any).mockResolvedValue([buildOrganization()]);

    const res = await request(app).get('/organizations');

    expect(res.status).toBe(200);
    expect(res.body.organizations).toHaveLength(1);
    expect(res.body.organizations[0].membership.roles).toEqual(['owner', 'admin']);
  });

  it('creates an organization with an owner membership', async () => {
    (Organization.findOne as any).mockResolvedValue(null);
    (Organization.create as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.create as any).mockResolvedValue(buildOrganizationMembership());

    const res = await request(app).post('/organizations').send({ name: 'Acme, Inc.' });

    expect(res.status).toBe(201);
    expect(Organization.create).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'Acme, Inc.',
        slug: 'acme-inc',
        createdByUserId: 'user-1',
      }),
    );
    expect(OrganizationMembership.create).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: testOrganizationId,
        userId: 'user-1',
        roles: ['owner', 'admin'],
      }),
    );
  });

  it('adds an organization member by email', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(null);
    (User.findOne as any).mockResolvedValue(
      buildUser({
        id: 'a1863941-552c-428a-aecd-599814979e8d',
        email: 'member@example.com',
      }),
    );
    (OrganizationMembership.create as any).mockResolvedValue(
      buildOrganizationMembership({
        userId: 'a1863941-552c-428a-aecd-599814979e8d',
        roles: ['member'],
        scopes: ['billing:read'],
      }),
    );

    const res = await request(app)
      .post(`/organizations/${testOrganizationId}/members`)
      .send({
        email: 'member@example.com',
        scopes: ['billing:read'],
      });

    expect(res.status).toBe(201);
    expect(OrganizationMembership.create).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: testOrganizationId,
        userId: 'a1863941-552c-428a-aecd-599814979e8d',
        roles: ['member'],
        scopes: ['billing:read'],
      }),
    );
  });

  it('does not expose another organization to a non-member', async () => {
    (Organization.findByPk as any).mockResolvedValue(
      buildOrganization({
        id: '9c793c14-7009-4524-b889-23284c6999c2',
      }),
    );
    (OrganizationMembership.findOne as any).mockResolvedValue(null);

    const res = await request(app).get('/organizations/9c793c14-7009-4524-b889-23284c6999c2');

    expect(res.status).toBe(404);
  });

  it('requires members:read access before listing organization members', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(
      buildOrganizationMembership({
        roles: ['member'],
        scopes: ['organization:read'],
      }),
    );

    const res = await request(app).get(`/organizations/${testOrganizationId}/members`);

    expect(res.status).toBe(404);
    expect(OrganizationMembership.findAll).not.toHaveBeenCalled();
  });

  it('switches the current session organization', async () => {
    const session = buildSession({ id: 'session-1', userId: 'user-1' });

    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());
    (Session.findOne as any).mockResolvedValue(session);
    (signAccessToken as any).mockResolvedValue('organization-access-token');
    (getSystemConfig as any).mockResolvedValue({ access_token_ttl: '15m' });

    const res = await request(app).post(`/organizations/${testOrganizationId}/switch`);

    expect(res.status).toBe(200);
    expect(session.update).toHaveBeenCalledWith({
      organizationId: testOrganizationId,
    });
    expect(signAccessToken).toHaveBeenCalledWith(
      'session-1',
      'user-1',
      ['user'],
      testOrganizationId,
    );
  });
});

describe('admin organizations', () => {
  it('lists all organizations for admins', async () => {
    (Organization.findAll as any).mockResolvedValue([buildOrganization()]);
    (OrganizationMembership.count as any).mockResolvedValue(2);

    const res = await request(app).get('/admin/organizations');

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.organizations[0].memberCount).toBe(2);
  });
});
