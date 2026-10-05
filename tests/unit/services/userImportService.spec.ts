import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { OrganizationMembership } from '../../../src/models/organizationMemberships.js';
import { Organization } from '../../../src/models/organizations.js';
import { UserExternalId } from '../../../src/models/userExternalIds.js';
import { User } from '../../../src/models/users.js';
import { importUsers } from '../../../src/services/userImportService.js';
import {
  buildOrganization,
  buildOrganizationMembership,
  testOrganizationId,
} from '../../factories/organizationFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

const existingId = '0b9a6d3e-6a3f-4a5e-9d0a-1f2e3d4c5b6a';

function existingUser(overrides: Record<string, unknown> = {}) {
  return { id: existingId, email: 'ada@example.com', phone: null, roles: ['user'], ...overrides };
}

/**
 * The service filters with `Op.in`, a symbol key, so each finder is answered by
 * looking at which plain column the query names.
 */
function mockUsers({
  byEmail = [],
  byPhone = [],
  byId = [],
}: { byEmail?: unknown[]; byPhone?: unknown[]; byId?: unknown[] } = {}) {
  (User.findAll as any).mockImplementation(async ({ where }: any) => {
    if ('email' in where) return byEmail;
    if ('phone' in where) return byPhone;
    if ('id' in where) return byId;
    return [];
  });
}

function mockLinks({
  byExternalId = [],
  byUser = [],
}: { byExternalId?: unknown[]; byUser?: unknown[] } = {}) {
  (UserExternalId.findAll as any).mockImplementation(async ({ where }: any) =>
    'externalId' in where ? byExternalId : byUser,
  );
}

function mockOrganizations(orgs: unknown[]) {
  (Organization.findAll as any).mockResolvedValue(orgs);
}

beforeEach(() => {
  vi.clearAllMocks();
  (getSystemConfig as any).mockResolvedValue(
    buildSystemConfig({ default_roles: ['user'], available_roles: ['user', 'clerk', 'admin'] }),
  );
  mockUsers();
  mockLinks();
  mockOrganizations([]);
  (OrganizationMembership.findAll as any).mockResolvedValue([]);
  (User.create as any).mockImplementation(async (values: any) => ({ id: 'new-user', ...values }));
});

describe('importUsers', () => {
  it('creates a user with the default roles plus the row roles and links the external id', async () => {
    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ externalId: 'emp-1', email: 'Grace@Example.com', roles: ['clerk'] }],
    });

    expect(User.create).toHaveBeenCalledWith(
      { email: 'grace@example.com', phone: null, roles: ['user', 'clerk'] },
      expect.anything(),
    );
    expect(UserExternalId.create).toHaveBeenCalledWith(
      { userId: 'new-user', source: 'csv', externalId: 'emp-1' },
      expect.anything(),
    );
    expect(response.results[0]).toEqual({
      index: 0,
      email: 'grace@example.com',
      externalId: 'emp-1',
      status: 'created',
      userId: 'new-user',
      changes: ['created'],
    });
    expect(response.summary).toEqual({ created: 1, updated: 0, unchanged: 0, rejected: 0 });
  });

  it('writes nothing on a dry run and reports what would happen', async () => {
    const response = await importUsers({
      source: 'csv',
      dryRun: true,
      users: [{ externalId: 'emp-1', email: 'grace@example.com' }],
    });

    expect(User.create).not.toHaveBeenCalled();
    expect(UserExternalId.create).not.toHaveBeenCalled();
    expect(User.sequelize!.transaction).not.toHaveBeenCalled();
    expect(response.dryRun).toBe(true);
    expect(response.results[0].status).toBe('created');
    expect(response.results[0].userId).toBeUndefined();
  });

  it('matches a re-run on the external id and adds only the missing roles', async () => {
    const user = existingUser({ roles: ['user', 'manager'] });
    mockLinks({ byExternalId: [{ userId: existingId, externalId: 'emp-1' }] });
    mockUsers({ byId: [user] });
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig({ available_roles: [] }));

    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ externalId: 'emp-1', email: 'ada@example.com', roles: ['user', 'clerk'] }],
    });

    expect(User.update).toHaveBeenCalledWith(
      { roles: ['user', 'manager', 'clerk'] },
      { where: { id: existingId }, transaction: expect.anything() },
    );
    expect(UserExternalId.create).not.toHaveBeenCalled();
    expect(response.results[0]).toMatchObject({ status: 'updated', changes: ['roles'] });
  });

  it('reports unchanged and writes nothing when the user already matches', async () => {
    mockLinks({ byExternalId: [{ userId: existingId, externalId: 'emp-1' }] });
    mockUsers({ byId: [existingUser()] });

    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ externalId: 'emp-1', email: 'ada@example.com', roles: ['user'] }],
    });

    expect(User.sequelize!.transaction).not.toHaveBeenCalled();
    expect(response.results[0]).toEqual({
      index: 0,
      email: 'ada@example.com',
      externalId: 'emp-1',
      status: 'unchanged',
      userId: existingId,
    });
  });

  it('refuses to move a linked account to a different email', async () => {
    mockLinks({ byExternalId: [{ userId: existingId, externalId: 'emp-1' }] });
    mockUsers({ byId: [existingUser()] });

    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ externalId: 'emp-1', email: 'someone-else@example.com' }],
    });

    expect(response.results[0]).toMatchObject({ status: 'rejected', reason: 'email_mismatch' });
    expect(User.update).not.toHaveBeenCalled();
  });

  it('links an existing account found by email', async () => {
    mockUsers({ byEmail: [existingUser()] });

    const response = await importUsers({
      source: 'entra-id',
      dryRun: false,
      users: [{ externalId: 'oid-9', email: 'ada@example.com' }],
    });

    expect(UserExternalId.create).toHaveBeenCalledWith(
      { userId: existingId, source: 'entra-id', externalId: 'oid-9' },
      expect.anything(),
    );
    expect(response.results[0]).toMatchObject({ status: 'updated', changes: ['linked'] });
  });

  it('rejects linking an account that already carries another id from the same source', async () => {
    mockUsers({ byEmail: [existingUser()] });
    mockLinks({ byUser: [{ userId: existingId, externalId: 'oid-1' }] });

    const response = await importUsers({
      source: 'entra-id',
      dryRun: false,
      users: [{ externalId: 'oid-2', email: 'ada@example.com' }],
    });

    expect(response.results[0]).toMatchObject({
      status: 'rejected',
      reason: 'external_id_conflict',
    });
  });

  it('refuses to link an external id to an existing administrator', async () => {
    mockUsers({ byEmail: [existingUser({ roles: ['user', 'admin:write'] })] });

    const response = await importUsers({
      source: 'entra-id',
      dryRun: false,
      users: [{ externalId: 'oid-9', email: 'ada@example.com' }],
    });

    expect(response.results[0]).toMatchObject({
      status: 'rejected',
      reason: 'admin_role_not_allowed',
      detail: 'existing account holds an admin role',
    });
    expect(UserExternalId.create).not.toHaveBeenCalled();
  });

  it('refuses admin roles, including scoped ones', async () => {
    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [
        { email: 'a@example.com', roles: ['admin'] },
        { email: 'b@example.com', roles: ['user', 'admin:read'] },
      ],
    });

    expect(response.results.map((r) => r.reason)).toEqual([
      'admin_role_not_allowed',
      'admin_role_not_allowed',
    ]);
    expect(response.results[1].detail).toBe('admin:read');
    expect(User.create).not.toHaveBeenCalled();
  });

  it('rejects roles the instance does not offer', async () => {
    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ email: 'a@example.com', roles: ['wizard'] }],
    });

    expect(response.results[0]).toMatchObject({
      status: 'rejected',
      reason: 'role_unavailable',
      detail: 'wizard',
    });
  });

  it('rejects a row naming an organization that does not exist', async () => {
    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ email: 'a@example.com', organizations: [{ slug: 'nowhere' }] }],
    });

    expect(response.results[0]).toMatchObject({
      reason: 'organization_not_found',
      detail: 'nowhere',
    });
  });

  it('creates a membership by slug with the default member role', async () => {
    mockOrganizations([buildOrganization({ slug: 'parks' })]);

    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ email: 'a@example.com', organizations: [{ slug: 'parks' }] }],
    });

    expect(OrganizationMembership.create).toHaveBeenCalledWith(
      { organizationId: testOrganizationId, userId: 'new-user', roles: ['member'], scopes: [] },
      expect.anything(),
    );
    expect(response.results[0].changes).toEqual(['created', 'organizations']);
  });

  it('adds missing roles to an existing membership without removing any', async () => {
    mockUsers({ byEmail: [existingUser()] });
    mockOrganizations([buildOrganization()]);
    (OrganizationMembership.findAll as any).mockResolvedValue([
      buildOrganizationMembership({ userId: existingId, roles: ['member'], scopes: [] }),
    ]);

    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [
        {
          email: 'ada@example.com',
          organizations: [{ organizationId: testOrganizationId, roles: ['member', 'admin'] }],
        },
      ],
    });

    expect(OrganizationMembership.update).toHaveBeenCalledWith(
      { roles: ['member', 'admin'], scopes: [] },
      expect.objectContaining({ where: { id: expect.any(String) } }),
    );
    expect(response.results[0]).toMatchObject({ status: 'updated', changes: ['organizations'] });
  });

  it('rejects the later of two rows for the same person', async () => {
    const response = await importUsers({
      source: 'csv',
      dryRun: true,
      users: [
        { email: 'a@example.com' },
        { email: 'A@example.com' },
        { externalId: 'x', email: 'b@example.com' },
        { externalId: 'x', email: 'c@example.com' },
      ],
    });

    expect(response.results.map((r) => r.status)).toEqual([
      'created',
      'rejected',
      'created',
      'rejected',
    ]);
    expect(response.results[1].reason).toBe('duplicate_in_batch');
  });

  it('rejects a phone number held by another account and an invalid one', async () => {
    mockUsers({ byPhone: [existingUser({ phone: '+14155552671' })] });

    const response = await importUsers({
      source: 'csv',
      dryRun: true,
      users: [
        { email: 'a@example.com', phone: '+1 415 555 2671' },
        { email: 'b@example.com', phone: 'not-a-phone' },
      ],
    });

    expect(response.results.map((r) => r.reason)).toEqual(['phone_in_use', 'phone_invalid']);
  });

  it('fills a missing phone on an existing account but never replaces one', async () => {
    mockUsers({ byEmail: [existingUser({ phone: '+14155550000' })] });

    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ email: 'ada@example.com', phone: '+14155552671' }],
    });

    expect(response.results[0].status).toBe('unchanged');
    expect(User.update).not.toHaveBeenCalled();
  });

  it('rejects a row whose write fails and carries on with the rest', async () => {
    (User.create as any)
      .mockRejectedValueOnce(new Error('unique violation'))
      .mockImplementationOnce(async (values: any) => ({ id: 'second', ...values }));

    const response = await importUsers({
      source: 'csv',
      dryRun: false,
      users: [{ email: 'a@example.com' }, { email: 'b@example.com' }],
    });

    expect(response.results[0]).toMatchObject({ status: 'rejected', reason: 'write_failed' });
    expect(response.results[1]).toMatchObject({ status: 'created', userId: 'second' });
    expect(response.summary).toEqual({ created: 1, updated: 0, unchanged: 0, rejected: 1 });
  });
});
