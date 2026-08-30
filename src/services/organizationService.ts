/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Op } from 'sequelize';

import { hasScopedRole } from '../lib/scopedRoles.js';
import { OrganizationMembership } from '../models/organizationMemberships.js';
import { Organization } from '../models/organizations.js';
import { User } from '../models/users.js';

export type OrganizationRole = 'owner' | 'admin' | 'member';

export interface SerializedOrganizationMembership {
  id: string;
  organizationId: string;
  userId: string;
  roles: string[];
  scopes: string[];
  createdAt: Date;
  updatedAt: Date;
  user?: {
    id: string;
    email: string;
    phone: string | null;
    roles: string[];
  };
}

export interface SerializedOrganization {
  id: string;
  name: string;
  slug: string;
  createdByUserId: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
  updatedAt: Date;
  membership?: SerializedOrganizationMembership;
  memberCount?: number;
}

function slugify(value: string) {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      // Single dash rather than `-+`: the collapse above leaves no two adjacent, so one is
      // all there can be, and matching a run would backtrack over an input of many dashes
      // for a repetition that cannot occur.
      .replace(/^-|-$/g, '')
      .slice(0, 80)
  );
}

export function normalizeOrganizationSlug(name: string, slug?: string | null) {
  const normalized = slugify(slug || name);

  if (normalized) {
    return normalized;
  }

  return `organization-${Date.now()}`;
}

export function normalizeMembershipValues(input?: string[] | null) {
  if (!Array.isArray(input)) return [];

  return Array.from(
    new Set(
      input
        .map((item) => item.trim())
        .filter((item) => item.length > 0)
        .slice(0, 50),
    ),
  );
}

export function normalizeOrganizationRoles(input?: string[] | null) {
  const roles = normalizeMembershipValues(input);
  return roles.length > 0 ? roles : ['member'];
}

async function buildUniqueSlug(slug: string) {
  let candidate = slug;
  let suffix = 1;

  while (await Organization.findOne({ where: { slug: candidate } })) {
    suffix += 1;
    candidate = `${slug}-${suffix}`;
  }

  return candidate;
}

export function serializeMembership(
  membership: OrganizationMembership,
  user?: User,
): SerializedOrganizationMembership {
  return {
    id: membership.id,
    organizationId: membership.organizationId,
    userId: membership.userId,
    roles: Array.isArray(membership.roles) ? membership.roles : [],
    scopes: Array.isArray(membership.scopes) ? membership.scopes : [],
    createdAt: membership.createdAt,
    updatedAt: membership.updatedAt,
    ...(user
      ? {
          user: {
            id: user.id,
            email: user.email,
            phone: user.phone,
            roles: user.roles ?? [],
          },
        }
      : {}),
  };
}

export function serializeOrganization(
  organization: Organization,
  membership?: OrganizationMembership | null,
  memberCount?: number,
): SerializedOrganization {
  return {
    id: organization.id,
    name: organization.name,
    slug: organization.slug,
    createdByUserId: organization.createdByUserId,
    metadata: organization.metadata ?? null,
    createdAt: organization.createdAt,
    updatedAt: organization.updatedAt,
    ...(membership ? { membership: serializeMembership(membership) } : {}),
    ...(memberCount === undefined ? {} : { memberCount }),
  };
}

export async function createOrganizationForUser({
  name,
  slug,
  user,
  metadata,
}: {
  name: string;
  slug?: string | null;
  user: User;
  metadata?: Record<string, unknown> | null;
}) {
  const uniqueSlug = await buildUniqueSlug(normalizeOrganizationSlug(name, slug));
  const organization = await Organization.create({
    name,
    slug: uniqueSlug,
    createdByUserId: user.id,
    metadata: metadata ?? null,
  });

  const membership = await OrganizationMembership.create({
    organizationId: organization.id,
    userId: user.id,
    roles: ['owner', 'admin'],
    scopes: ['organization:read', 'organization:write', 'members:read', 'members:write'],
  });

  return { organization, membership };
}

export async function findMembership(userId: string, organizationId: string) {
  return OrganizationMembership.findOne({
    where: {
      organizationId,
      userId,
    },
  });
}

export function isOrganizationManager(user: User, membership?: OrganizationMembership | null) {
  if (hasScopedRole(user.roles, 'admin:write')) return true;
  return Boolean(membership?.roles?.some((role) => role === 'owner' || role === 'admin'));
}

export function hasOrganizationScope(
  user: User,
  membership: OrganizationMembership | null | undefined,
  requiredScope: string,
) {
  const requiredAdminScope = requiredScope.endsWith(':write') ? 'admin:write' : 'admin:read';
  if (hasScopedRole(user.roles, requiredAdminScope)) return true;
  if (isOrganizationManager(user, membership)) return true;
  return hasScopedRole(membership?.scopes, requiredScope);
}

export async function requireOrganizationAccess(user: User, organizationId: string) {
  const organization = await Organization.findByPk(organizationId);

  if (!organization) {
    return { organization: null, membership: null };
  }

  const membership = await findMembership(user.id, organizationId);

  if (!membership && !hasScopedRole(user.roles, 'admin:read')) {
    return { organization: null, membership: null };
  }

  if (membership && !hasOrganizationScope(user, membership, 'organization:read')) {
    return { organization: null, membership: null };
  }

  return { organization, membership };
}

export async function requireOrganizationManager(user: User, organizationId: string) {
  const { organization, membership } = await requireOrganizationAccess(user, organizationId);

  if (!organization || !isOrganizationManager(user, membership)) {
    return { organization: null, membership: null };
  }

  return { organization, membership };
}

export async function listOrganizationsForUser(userId: string) {
  const memberships = await OrganizationMembership.findAll({
    where: { userId },
    order: [['createdAt', 'ASC']],
  });

  const organizationIds = memberships.map((membership) => membership.organizationId);

  if (organizationIds.length === 0) {
    return [];
  }

  const organizations = await Organization.findAll({
    where: { id: { [Op.in]: organizationIds } },
    order: [['createdAt', 'ASC']],
  });

  const membershipsByOrg = new Map(
    memberships.map((membership) => [membership.organizationId, membership]),
  );

  return organizations.map((organization) =>
    serializeOrganization(organization, membershipsByOrg.get(organization.id)),
  );
}

export async function listAllOrganizations() {
  const organizations = await Organization.findAll({
    order: [['createdAt', 'ASC']],
  });

  const counts = await Promise.all(
    organizations.map((organization) =>
      OrganizationMembership.count({ where: { organizationId: organization.id } }),
    ),
  );

  return organizations.map((organization, index) =>
    serializeOrganization(organization, null, counts[index]),
  );
}

export async function getDefaultOrganizationIdForUser(userId: string) {
  const membership = await OrganizationMembership.findOne({
    where: { userId },
    order: [['createdAt', 'ASC']],
  });

  return membership?.organizationId ?? null;
}

export async function listOrganizationMembers(organizationId: string) {
  const memberships = await OrganizationMembership.findAll({
    where: { organizationId },
    order: [['createdAt', 'ASC']],
  });

  const users = await User.findAll({
    where: {
      id: { [Op.in]: memberships.map((membership) => membership.userId) },
    },
  });
  const usersById = new Map(users.map((user) => [user.id, user]));

  return memberships.map((membership) =>
    serializeMembership(membership, usersById.get(membership.userId)),
  );
}

export async function countOwners(organizationId: string) {
  const memberships = await OrganizationMembership.findAll({
    where: { organizationId },
  });

  return memberships.filter((membership) => membership.roles?.includes('owner')).length;
}
