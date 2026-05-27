/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { signAccessToken } from '../lib/token.js';
import { OrganizationMembership } from '../models/organizationMemberships.js';
import { Organization } from '../models/organizations.js';
import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';
import {
  countOwners,
  createOrganizationForUser,
  findMembership,
  listAllOrganizations,
  listOrganizationMembers,
  listOrganizationsForUser,
  normalizeMembershipValues,
  normalizeOrganizationRoles,
  normalizeOrganizationSlug,
  requireOrganizationAccess,
  requireOrganizationManager,
  serializeMembership,
  serializeOrganization,
} from '../services/organizationService.js';
import { AuthenticatedRequest } from '../types/types.js';
import { parseDurationToSeconds } from '../utils/utils.js';

function authUser(req: Request) {
  return (req as AuthenticatedRequest).user;
}

function currentOrganizationId(req: Request) {
  return (req as AuthenticatedRequest).organizationId ?? null;
}

function currentSessionId(req: Request) {
  return (req as AuthenticatedRequest).sessionId;
}

export async function listOrganizations(req: Request, res: Response) {
  const user = authUser(req);
  const organizations = await listOrganizationsForUser(user.id);

  return res.json({
    organizations,
    activeOrganizationId: currentOrganizationId(req),
  });
}

export async function listAdminOrganizations(req: Request, res: Response) {
  const organizations = await listAllOrganizations();
  return res.json({ organizations, total: organizations.length });
}

export async function createOrganization(req: Request, res: Response) {
  const user = authUser(req);
  const { name, slug, metadata } = req.body;
  const { organization, membership } = await createOrganizationForUser({
    name,
    slug,
    user,
    metadata,
  });

  return res.status(201).json({
    organization: serializeOrganization(organization, membership),
  });
}

export async function getOrganization(req: Request, res: Response) {
  const user = authUser(req);
  const { organizationId } = req.params;
  const { organization, membership } = await requireOrganizationAccess(user, organizationId);

  if (!organization) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  return res.json({
    organization: serializeOrganization(organization, membership),
  });
}

export async function updateOrganization(req: Request, res: Response) {
  const user = authUser(req);
  const { organizationId } = req.params;
  const { organization, membership } = await requireOrganizationManager(user, organizationId);

  if (!organization) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  const updates: Partial<Pick<Organization, 'name' | 'slug' | 'metadata'>> = {};

  if (req.body.name !== undefined) {
    updates.name = req.body.name;
  }

  if (req.body.slug !== undefined) {
    updates.slug = normalizeOrganizationSlug(req.body.slug);
  }

  if (req.body.metadata !== undefined) {
    updates.metadata = req.body.metadata;
  }

  await organization.update(updates);

  return res.json({
    organization: serializeOrganization(organization, membership),
  });
}

export async function switchOrganization(req: Request, res: Response) {
  const user = authUser(req);
  const { organizationId } = req.params;
  const sessionId = currentSessionId(req);
  const { organization, membership } = await requireOrganizationAccess(user, organizationId);

  if (!organization || !membership) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  if (!sessionId) {
    return res.status(400).json({ error: 'Session context required' });
  }

  const session = await Session.findOne({
    where: {
      id: sessionId,
      userId: user.id,
    },
  });

  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  await session.update({ organizationId: organization.id });
  const token = await signAccessToken(session.id, user.id, user.roles, organization.id);

  const { access_token_ttl } = await getSystemConfig();
  return res.json({
    message: 'Success',
    token,
    sub: user.id,
    sessionId: session.id,
    organizationId: organization.id,
    organization: serializeOrganization(organization, membership),
    ttl: parseDurationToSeconds(access_token_ttl || '15m'),
  });
}

export async function listMembers(req: Request, res: Response) {
  const user = authUser(req);
  const { organizationId } = req.params;
  const { organization } = await requireOrganizationAccess(user, organizationId);

  if (!organization) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  const members = await listOrganizationMembers(organizationId);
  return res.json({ members, total: members.length });
}

export async function addMember(req: Request, res: Response) {
  const user = authUser(req);
  const { organizationId } = req.params;
  const { organization } = await requireOrganizationManager(user, organizationId);

  if (!organization) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  const memberUser = req.body.userId
    ? await User.findByPk(req.body.userId)
    : await User.findOne({ where: { email: req.body.email.toLowerCase() } });

  if (!memberUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  const existing = await findMembership(memberUser.id, organizationId);

  if (existing) {
    return res.status(409).json({ error: 'User is already an organization member' });
  }

  const membership = await OrganizationMembership.create({
    organizationId,
    userId: memberUser.id,
    roles: normalizeOrganizationRoles(req.body.roles),
    scopes: normalizeMembershipValues(req.body.scopes),
  });

  return res.status(201).json({
    membership: serializeMembership(membership, memberUser),
  });
}

export async function updateMember(req: Request, res: Response) {
  const user = authUser(req);
  const { organizationId, userId } = req.params;
  const { organization } = await requireOrganizationManager(user, organizationId);

  if (!organization) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  const membership = await findMembership(userId, organizationId);

  if (!membership) {
    return res.status(404).json({ error: 'Membership not found' });
  }

  const nextRoles =
    req.body.roles === undefined ? membership.roles : normalizeOrganizationRoles(req.body.roles);

  if (membership.roles?.includes('owner') && !nextRoles.includes('owner')) {
    const ownerCount = await countOwners(organizationId);
    if (ownerCount <= 1) {
      return res.status(400).json({ error: 'Organization must keep at least one owner' });
    }
  }

  await membership.update({
    roles: nextRoles,
    scopes:
      req.body.scopes === undefined
        ? membership.scopes
        : normalizeMembershipValues(req.body.scopes),
  });

  const memberUser = await User.findByPk(userId);

  return res.json({
    membership: serializeMembership(membership, memberUser ?? undefined),
  });
}

export async function removeMember(req: Request, res: Response) {
  const user = authUser(req);
  const { organizationId, userId } = req.params;
  const { organization } = await requireOrganizationManager(user, organizationId);

  if (!organization) {
    return res.status(404).json({ error: 'Organization not found' });
  }

  const membership = await findMembership(userId, organizationId);

  if (!membership) {
    return res.status(404).json({ error: 'Membership not found' });
  }

  if (membership.roles?.includes('owner')) {
    const ownerCount = await countOwners(organizationId);
    if (ownerCount <= 1) {
      return res.status(400).json({ error: 'Organization must keep at least one owner' });
    }
  }

  await membership.destroy();

  return res.json({ message: 'Success' });
}
