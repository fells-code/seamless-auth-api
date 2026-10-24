import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { OrganizationMembership } from '../../../src/models/organizationMemberships.js';
import { Organization } from '../../../src/models/organizations.js';
import { User } from '../../../src/models/users.js';
import { validateBearerToken } from '../../../src/services/sessionService.js';
import {
  buildOrganization,
  buildOrganizationMembership,
  testOrganizationId,
} from '../../factories/organizationFactory';
import { Session } from '../../../src/models/sessions.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory.js';
import { buildUser } from '../../factories/userFactory.js';

// Driven through the real bearer and admin checks, which the other organization specs stub out.
vi.unmock('../../../src/middleware/attachAuthMiddleware.js');
vi.unmock('../../../src/middleware/requireAdmin.js');

const MEMBERS = `/organizations/${testOrganizationId}/members`;
const memberId = 'a1863941-552c-428a-aecd-599814979e8d';
let app: Application;

function asRoles(roles: string[]) {
  vi.mocked(validateBearerToken).mockResolvedValue({
    user: buildUser({ id: 'user-1', roles }),
    sessionId: 'session-1',
  } as never);
}

beforeAll(async () => {
  const { createApp } = await import('../../../src/app.js');

  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
  (Organization.findByPk as any).mockResolvedValue(buildOrganization());
  (OrganizationMembership.findOne as any).mockResolvedValue(
    buildOrganizationMembership({ scopes: ['organization:read', 'members:read', 'members:write'] }),
  );
});

describe('POST /organizations/{organizationId}/members', () => {
  it('refuses an organization owner who is not an administrator', async () => {
    asRoles(['user']);

    const res = await request(app)
      .post(MEMBERS)
      .set('Authorization', 'Bearer token')
      .send({ email: 'someone@example.com' });

    expect(res.status).toBe(403);
    expect(User.findOne).not.toHaveBeenCalled();
    expect(OrganizationMembership.create).not.toHaveBeenCalled();
  });

  it('lets an administrator add a member', async () => {
    asRoles(['admin:write']);
    (OrganizationMembership.findOne as any)
      .mockResolvedValueOnce(buildOrganizationMembership())
      .mockResolvedValueOnce(null);
    (User.findOne as any).mockResolvedValue(buildUser({ id: memberId }));
    (OrganizationMembership.create as any).mockResolvedValue(
      buildOrganizationMembership({ userId: memberId, roles: ['member'] }),
    );

    const res = await request(app)
      .post(MEMBERS)
      .set('Authorization', 'Bearer token')
      .send({ email: 'someone@example.com' });

    expect(res.status).toBe(201);
  });
});

describe('GET /organizations/{organizationId}/members', () => {
  beforeEach(() => {
    (OrganizationMembership.findAll as any).mockResolvedValue([
      buildOrganizationMembership({ userId: memberId, roles: ['member'] }),
    ]);
    (User.findAll as any).mockResolvedValue([
      buildUser({ id: memberId, phone: '+15550100', roles: ['user', 'admin:write'] }),
    ]);
  });

  it('leaves out phone numbers and global roles for a non-administrator', async () => {
    asRoles(['user']);

    const res = await request(app).get(MEMBERS).set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(res.body.members[0].user).toEqual(
      expect.objectContaining({ id: memberId, phone: null, roles: [] }),
    );
  });

  it('shows them to an administrator', async () => {
    asRoles(['admin:read']);

    const res = await request(app).get(MEMBERS).set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(res.body.members[0].user).toEqual(
      expect.objectContaining({ phone: '+15550100', roles: ['user', 'admin:write'] }),
    );
  });
});
