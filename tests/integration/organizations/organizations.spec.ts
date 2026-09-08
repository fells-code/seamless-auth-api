import { Op, UniqueConstraintError } from 'sequelize';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { switchOrganization } from '../../../src/controllers/organizations.js';
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

const otherUserId = 'a1863941-552c-428a-aecd-599814979e8d';

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
    // Both writes take a transaction, because an organization with no membership is
    // unreachable: access is granted through membership and nothing deletes an
    // organization, so a failure between them would strand the row.
    expect(Organization.create).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'Acme, Inc.',
        slug: 'acme-inc',
        createdByUserId: 'user-1',
      }),
      expect.objectContaining({ transaction: expect.anything() }),
    );
    expect(OrganizationMembership.create).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: testOrganizationId,
        userId: 'user-1',
        roles: ['owner', 'admin'],
      }),
      expect.objectContaining({ transaction: expect.anything() }),
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

describe('getOrganization', () => {
  it('returns the organization for a member', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());

    const res = await request(app).get(`/organizations/${testOrganizationId}`);

    expect(res.status).toBe(200);
    expect(res.body.organization.id).toBe(testOrganizationId);
    expect(res.body.organization.membership.roles).toEqual(['owner', 'admin']);
  });
});

describe('updateOrganization', () => {
  it('returns 404 when the organization is missing', async () => {
    (Organization.findByPk as any).mockResolvedValue(null);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}`)
      .send({ name: 'Renamed' });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Organization not found');
  });

  it('applies name, normalized slug, and metadata updates', async () => {
    const organization = buildOrganization();
    (Organization.findByPk as any).mockResolvedValue(organization);
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}`)
      .send({ name: 'Renamed', slug: 'New Slug', metadata: { plan: 'pro' } });

    expect(res.status).toBe(200);
    expect(organization.update).toHaveBeenCalledWith({
      name: 'Renamed',
      slug: 'new-slug',
      metadata: { plan: 'pro' },
    });
  });

  it('performs an empty update when no fields are supplied', async () => {
    const organization = buildOrganization();
    (Organization.findByPk as any).mockResolvedValue(organization);
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());

    const res = await request(app).patch(`/organizations/${testOrganizationId}`).send({});

    expect(res.status).toBe(200);
    expect(organization.update).toHaveBeenCalledWith({});
  });
});

describe('switchOrganization', () => {
  it('returns 404 when the organization is not accessible', async () => {
    (Organization.findByPk as any).mockResolvedValue(null);

    const res = await request(app).post(`/organizations/${testOrganizationId}/switch`);

    expect(res.status).toBe(404);
  });

  it('returns 404 when the session cannot be found', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());
    (Session.findOne as any).mockResolvedValue(null);

    const res = await request(app).post(`/organizations/${testOrganizationId}/switch`);

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Session not found');
  });

  it('falls back to the default ttl when access_token_ttl is unset', async () => {
    const session = buildSession({ id: 'session-1', userId: 'user-1' });
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());
    (Session.findOne as any).mockResolvedValue(session);
    (signAccessToken as any).mockResolvedValue('organization-access-token');
    (getSystemConfig as any).mockResolvedValue({});

    const res = await request(app).post(`/organizations/${testOrganizationId}/switch`);

    expect(res.status).toBe(200);
    expect(res.body.ttl).toBe(900);
    expect(res.body.token).toBe('organization-access-token');
  });

  it('returns 400 when the session context is missing', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());

    const req: any = {
      user: { id: 'user-1', roles: ['user'] },
      params: { organizationId: testOrganizationId },
    };
    const res: any = {};
    res.status = vi.fn().mockReturnValue(res);
    res.json = vi.fn().mockReturnValue(res);

    await switchOrganization(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Session context required' });
  });
});

describe('listMembers', () => {
  it('lists members for a manager', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());
    (OrganizationMembership.findAll as any).mockResolvedValue([buildOrganizationMembership()]);
    (User.findAll as any).mockResolvedValue([buildUser({ id: 'user-1' })]);

    const res = await request(app).get(`/organizations/${testOrganizationId}/members`);

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.members).toHaveLength(1);
  });
});

describe('addMember', () => {
  it('returns 404 when the organization is not manageable', async () => {
    (Organization.findByPk as any).mockResolvedValue(null);

    const res = await request(app)
      .post(`/organizations/${testOrganizationId}/members`)
      .send({ email: 'member@example.com' });

    expect(res.status).toBe(404);
  });

  it('adds a member looked up by userId', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(null);
    (User.findByPk as any).mockResolvedValue(buildUser({ id: otherUserId }));
    (OrganizationMembership.create as any).mockResolvedValue(
      buildOrganizationMembership({ userId: otherUserId, roles: ['admin'] }),
    );

    const res = await request(app)
      .post(`/organizations/${testOrganizationId}/members`)
      .send({ userId: otherUserId, roles: ['admin'] });

    expect(res.status).toBe(201);
    expect(User.findByPk).toHaveBeenCalledWith(otherUserId);
    expect(OrganizationMembership.create).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: testOrganizationId,
        userId: otherUserId,
        roles: ['admin'],
      }),
    );
  });

  it('returns 404 when the target user does not exist', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());
    (User.findByPk as any).mockResolvedValue(null);

    const res = await request(app)
      .post(`/organizations/${testOrganizationId}/members`)
      .send({ userId: otherUserId });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found');
    expect(OrganizationMembership.create).not.toHaveBeenCalled();
  });

  it('returns 409 when the user is already a member', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(buildOrganizationMembership({ userId: otherUserId }));
    (User.findByPk as any).mockResolvedValue(buildUser({ id: otherUserId }));

    const res = await request(app)
      .post(`/organizations/${testOrganizationId}/members`)
      .send({ userId: otherUserId });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('User is already an organization member');
    expect(OrganizationMembership.create).not.toHaveBeenCalled();
  });

  // The membership lookup and the insert are two statements, so the duplicate the lookup
  // exists to catch can still arrive at the index. It is the same duplicate.
  it('returns 409 when a concurrent add loses the race to the unique index', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(null);
    (User.findByPk as any).mockResolvedValue(buildUser({ id: otherUserId }));
    (OrganizationMembership.create as any).mockRejectedValue(
      new UniqueConstraintError({ fields: { organization_id: testOrganizationId } }),
    );

    const res = await request(app)
      .post(`/organizations/${testOrganizationId}/members`)
      .send({ userId: otherUserId });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('User is already an organization member');
  });

  it('lets any other failure reach the generic handler', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(null);
    (User.findByPk as any).mockResolvedValue(buildUser({ id: otherUserId }));
    (OrganizationMembership.create as any).mockRejectedValue(new Error('connection reset'));

    const res = await request(app)
      .post(`/organizations/${testOrganizationId}/members`)
      .send({ userId: otherUserId });

    expect(res.status).toBe(500);
  });
});

describe('updateMember', () => {
  it('returns 404 when the organization is not manageable', async () => {
    (Organization.findByPk as any).mockResolvedValue(null);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${otherUserId}`)
      .send({ roles: ['member'] });

    expect(res.status).toBe(404);
  });

  it('returns 404 when the membership does not exist', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(null);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${otherUserId}`)
      .send({ roles: ['member'] });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Membership not found');
  });

  it('rejects demoting the final owner', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(
        buildOrganizationMembership({ userId: otherUserId, roles: ['owner'] }),
      );
    (OrganizationMembership.findAll as any).mockResolvedValue([
      buildOrganizationMembership({ roles: ['owner'] }),
    ]);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${otherUserId}`)
      .send({ roles: ['member'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Organization must keep at least one owner');
  });

  it('demotes an owner when another owner remains', async () => {
    const target = buildOrganizationMembership({ userId: otherUserId, roles: ['owner'] });
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(target);
    (OrganizationMembership.findAll as any).mockResolvedValue([
      buildOrganizationMembership({ roles: ['owner'] }),
      buildOrganizationMembership({ userId: otherUserId, roles: ['owner'] }),
    ]);
    (User.findByPk as any).mockResolvedValue(buildUser({ id: otherUserId }));

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${otherUserId}`)
      .send({ roles: ['member'], scopes: ['organization:read'] });

    expect(res.status).toBe(200);
    expect(target.update).toHaveBeenCalledWith({
      roles: ['member'],
      scopes: ['organization:read'],
    });
    expect(res.body.membership.user.id).toBe(otherUserId);
  });

  it('retains existing roles and scopes when the body omits them', async () => {
    const target = buildOrganizationMembership({
      userId: otherUserId,
      roles: ['member'],
      scopes: ['organization:read'],
    });
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(target);
    (User.findByPk as any).mockResolvedValue(null);

    const res = await request(app)
      .patch(`/organizations/${testOrganizationId}/members/${otherUserId}`)
      .send({});

    expect(res.status).toBe(200);
    expect(target.update).toHaveBeenCalledWith({
      roles: ['member'],
      scopes: ['organization:read'],
    });
    expect(res.body.membership.user).toBeUndefined();
  });
});

describe('removeMember', () => {
  it('returns 404 when the organization is not manageable', async () => {
    (Organization.findByPk as any).mockResolvedValue(null);

    const res = await request(app).delete(
      `/organizations/${testOrganizationId}/members/${otherUserId}`,
    );

    expect(res.status).toBe(404);
  });

  it('returns 404 when the membership does not exist', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(null);

    const res = await request(app).delete(
      `/organizations/${testOrganizationId}/members/${otherUserId}`,
    );

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Membership not found');
  });

  it('rejects removing the final owner', async () => {
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(
        buildOrganizationMembership({ userId: otherUserId, roles: ['owner'] }),
      );
    (OrganizationMembership.findAll as any).mockResolvedValue([
      buildOrganizationMembership({ roles: ['owner'] }),
    ]);

    const res = await request(app).delete(
      `/organizations/${testOrganizationId}/members/${otherUserId}`,
    );

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Organization must keep at least one owner');
  });

  it('removes a non-owner member', async () => {
    const target = buildOrganizationMembership({ userId: otherUserId, roles: ['member'] });
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(target);

    const res = await request(app).delete(
      `/organizations/${testOrganizationId}/members/${otherUserId}`,
    );

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
    expect(target.destroy).toHaveBeenCalled();
  });

  it('removes an owner when another owner remains', async () => {
    const target = buildOrganizationMembership({ userId: otherUserId, roles: ['owner'] });
    (Organization.findByPk as any).mockResolvedValue(buildOrganization());
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(target);
    (OrganizationMembership.findAll as any).mockResolvedValue([
      buildOrganizationMembership({ roles: ['owner'] }),
      buildOrganizationMembership({ userId: otherUserId, roles: ['owner'] }),
    ]);

    const res = await request(app).delete(
      `/organizations/${testOrganizationId}/members/${otherUserId}`,
    );

    expect(res.status).toBe(200);
    expect(target.destroy).toHaveBeenCalled();
  });
});

describe('admin organizations', () => {
  it('lists all organizations for admins', async () => {
    (Organization.findAll as any).mockResolvedValue([buildOrganization()]);
    (Organization.count as any).mockResolvedValue(1);
    (OrganizationMembership.count as any).mockResolvedValue(2);

    const res = await request(app).get('/admin/organizations');

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.organizations[0].memberCount).toBe(2);
    expect(Organization.findAll).toHaveBeenCalledWith(
      expect.objectContaining({ where: {}, limit: 50, offset: 0 }),
    );
  });

  // The count is of everything matching, not of the page, so the caller can tell there
  // is a second page to ask for.
  it('windows the list and counts past the page', async () => {
    (Organization.findAll as any).mockResolvedValue([buildOrganization()]);
    (Organization.count as any).mockResolvedValue(140);
    (OrganizationMembership.count as any).mockResolvedValue(0);

    const res = await request(app).get('/admin/organizations?limit=1&offset=20');

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(140);
    expect(res.body.organizations).toHaveLength(1);
    expect(Organization.findAll).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 1, offset: 20 }),
    );
  });

  it('filters on name and slug when a search term is given', async () => {
    (Organization.findAll as any).mockResolvedValue([buildOrganization()]);
    (Organization.count as any).mockResolvedValue(1);
    (OrganizationMembership.count as any).mockResolvedValue(0);

    // Padded on purpose: the term is trimmed before it reaches the query, so a copied
    // and pasted name does not search for a string nothing is stored with.
    const res = await request(app).get('/admin/organizations?search=%20%20acme%20%20');

    expect(res.status).toBe(200);

    const where = (Organization.findAll as any).mock.calls[0][0].where;
    expect(where[Op.or]).toEqual([
      { name: { [Op.iLike]: '%acme%' } },
      { slug: { [Op.iLike]: '%acme%' } },
    ]);
    // Both queries see the same filter, or the count would describe a different set
    // than the page.
    expect((Organization.count as any).mock.calls[0][0].where).toEqual(where);
  });

  it('rejects a window outside the allowed range', async () => {
    const res = await request(app).get('/admin/organizations?limit=500');

    expect(res.status).toBe(400);
    expect(Organization.findAll).not.toHaveBeenCalled();
  });

  // An all-whitespace term trims to nothing. Accepting it would build `%%`, which matches
  // every row, so a search that looks empty would silently return the unfiltered list.
  it('rejects a search term that is only whitespace', async () => {
    const res = await request(app).get('/admin/organizations?search=%20%20');

    expect(res.status).toBe(400);
    expect(Organization.findAll).not.toHaveBeenCalled();
  });

  it('deletes an organization and the memberships in it', async () => {
    const organization = buildOrganization();
    (Organization.findByPk as any).mockResolvedValue(organization);
    (OrganizationMembership.findOne as any).mockResolvedValue(buildOrganizationMembership());

    const res = await request(app).delete(`/admin/organizations/${testOrganizationId}`);

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Success');
    // Both writes take the same transaction: an organization whose memberships outlived
    // it would leave grants pointing at a row that is gone.
    expect(OrganizationMembership.destroy).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { organizationId: testOrganizationId },
        transaction: expect.anything(),
      }),
    );
    expect(organization.destroy).toHaveBeenCalledWith(
      expect.objectContaining({ transaction: expect.anything() }),
    );
  });

  it('answers 404 when deleting an organization that does not exist', async () => {
    (Organization.findByPk as any).mockResolvedValue(null);

    const res = await request(app).delete(`/admin/organizations/${testOrganizationId}`);

    expect(res.status).toBe(404);
    expect(OrganizationMembership.destroy).not.toHaveBeenCalled();
  });
});
