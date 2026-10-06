/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type {
  ImportUsersRequest,
  ImportUsersResponse,
  UserImportChange,
  UserImportRejection,
  UserImportResult,
  UserImportRow,
} from '@seamless-auth/types';
import { Op, Transaction } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { unavailableRoles } from '../lib/scopedRoles.js';
import { OrganizationMembership } from '../models/organizationMemberships.js';
import { Organization } from '../models/organizations.js';
import { UserExternalId } from '../models/userExternalIds.js';
import { User } from '../models/users.js';
import getLogger from '../utils/logger.js';
import { isValidPhoneNumber, normalizePhoneNumber } from '../utils/utils.js';
import { normalizeMembershipValues, normalizeOrganizationRoles } from './organizationService.js';

const logger = getLogger('userImportService');

interface MembershipPlan {
  organizationId: string;
  existing: OrganizationMembership | null;
  roles: string[];
  scopes: string[];
}

interface ApplyPlan {
  kind: 'apply';
  index: number;
  email: string;
  externalId?: string;
  user: User | null;
  roles: string[];
  phone: string | null;
  linkExternalId: boolean;
  memberships: MembershipPlan[];
  changes: UserImportChange[];
}

interface RejectPlan {
  kind: 'reject';
  index: number;
  email: string;
  externalId?: string;
  reason: UserImportRejection;
  detail?: string;
}

type RowPlan = ApplyPlan | RejectPlan;

/**
 * Imports mint ordinary accounts. An administrator is granted individually, through
 * the user update route, so a spreadsheet with one wrong column cannot hand the
 * instance to everyone in it.
 */
function isAdminRole(role: string) {
  return role === 'admin' || role.startsWith('admin:');
}

function dedupe(values: string[]) {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

function missingFrom(current: string[] | undefined, wanted: string[]) {
  const have = new Set(current ?? []);
  return wanted.filter((value) => !have.has(value));
}

function orgKey(ref: { organizationId?: string; slug?: string }) {
  return ref.organizationId ? `id:${ref.organizationId}` : `slug:${ref.slug!.trim()}`;
}

async function loadContext(request: ImportUsersRequest) {
  const rows = request.users;
  const emails = dedupe(rows.map((row) => row.email.toLowerCase()));
  const externalIds = dedupe(rows.flatMap((row) => (row.externalId ? [row.externalId] : [])));
  const phones = dedupe(
    rows.flatMap((row) => {
      const normalized = row.phone ? normalizePhoneNumber(row.phone) : null;
      return normalized ? [normalized] : [];
    }),
  );
  const refs = rows.flatMap((row) => row.organizations ?? []);
  const orgIds = dedupe(refs.flatMap((ref) => (ref.organizationId ? [ref.organizationId] : [])));
  const slugs = dedupe(refs.flatMap((ref) => (ref.slug ? [ref.slug] : [])));

  const [config, links, usersByEmailList, usersByPhoneList, orgsById, orgsBySlug] =
    await Promise.all([
      getSystemConfig(),
      externalIds.length
        ? UserExternalId.findAll({
            where: { source: request.source, externalId: { [Op.in]: externalIds } },
          })
        : Promise.resolve([]),
      User.findAll({ where: { email: { [Op.in]: emails } } }),
      phones.length ? User.findAll({ where: { phone: { [Op.in]: phones } } }) : Promise.resolve([]),
      orgIds.length
        ? Organization.findAll({ where: { id: { [Op.in]: orgIds } } })
        : Promise.resolve([]),
      slugs.length
        ? Organization.findAll({ where: { slug: { [Op.in]: slugs } } })
        : Promise.resolve([]),
    ]);

  const linkedUserIds = dedupe((links ?? []).map((link) => link.userId));
  const linkedUsers = linkedUserIds.length
    ? await User.findAll({ where: { id: { [Op.in]: linkedUserIds } } })
    : [];

  const usersById = new Map<string, User>();
  for (const user of [...(usersByEmailList ?? []), ...(linkedUsers ?? [])]) {
    usersById.set(user.id, user);
  }

  const knownUserIds = Array.from(usersById.keys());
  const resolvedOrgIds = dedupe([
    ...(orgsById ?? []).map((org) => org.id),
    ...(orgsBySlug ?? []).map((org) => org.id),
  ]);

  const [sourceLinksForUsers, memberships] = await Promise.all([
    knownUserIds.length
      ? UserExternalId.findAll({
          where: { source: request.source, userId: { [Op.in]: knownUserIds } },
        })
      : Promise.resolve([]),
    knownUserIds.length && resolvedOrgIds.length
      ? OrganizationMembership.findAll({
          where: {
            userId: { [Op.in]: knownUserIds },
            organizationId: { [Op.in]: resolvedOrgIds },
          },
        })
      : Promise.resolve([]),
  ]);

  const orgs = new Map<string, string>();
  for (const org of orgsById ?? []) orgs.set(`id:${org.id}`, org.id);
  for (const org of orgsBySlug ?? []) orgs.set(`slug:${org.slug}`, org.id);

  return {
    availableRoles: config?.available_roles ?? [],
    defaultRoles: config?.default_roles ?? [],
    userByExternalId: new Map(
      (links ?? []).map((link) => [link.externalId, usersById.get(link.userId) ?? null]),
    ),
    userByEmail: new Map((usersByEmailList ?? []).map((user) => [user.email, user])),
    userByPhone: new Map(
      (usersByPhoneList ?? []).flatMap((user) => (user.phone ? [[user.phone, user]] : [])),
    ),
    externalIdForUser: new Map(
      (sourceLinksForUsers ?? []).map((link) => [link.userId, link.externalId]),
    ),
    membership: new Map(
      (memberships ?? []).map((membership) => [
        `${membership.userId}:${membership.organizationId}`,
        membership,
      ]),
    ),
    orgs,
  };
}

type ImportContext = Awaited<ReturnType<typeof loadContext>>;

function planRow(
  row: UserImportRow,
  index: number,
  ctx: ImportContext,
  seen: { emails: Set<string>; externalIds: Set<string>; phones: Set<string> },
): RowPlan {
  const email = row.email.toLowerCase();
  const externalId = row.externalId?.trim() || undefined;
  const reject = (reason: UserImportRejection, detail?: string): RejectPlan => ({
    kind: 'reject',
    index,
    email,
    ...(externalId ? { externalId } : {}),
    reason,
    ...(detail ? { detail } : {}),
  });

  const phone = row.phone ? normalizePhoneNumber(row.phone) : null;
  if (row.phone && (!phone || !isValidPhoneNumber(row.phone))) {
    return reject('phone_invalid');
  }

  if (
    seen.emails.has(email) ||
    (externalId && seen.externalIds.has(externalId)) ||
    (phone && seen.phones.has(phone))
  ) {
    return reject('duplicate_in_batch');
  }
  seen.emails.add(email);
  if (externalId) seen.externalIds.add(externalId);
  if (phone) seen.phones.add(phone);

  const roles = dedupe(row.roles ?? []);
  const adminRoles = roles.filter(isAdminRole);
  if (adminRoles.length) {
    return reject('admin_role_not_allowed', adminRoles.join(', '));
  }
  if (ctx.availableRoles.length) {
    const unavailable = unavailableRoles(roles, ctx.availableRoles);
    if (unavailable.length) {
      return reject('role_unavailable', unavailable.join(', '));
    }
  }

  const orgRefs = row.organizations ?? [];
  const missingOrg = orgRefs.find((ref) => !ctx.orgs.has(orgKey(ref)));
  if (missingOrg) {
    return reject('organization_not_found', missingOrg.organizationId ?? missingOrg.slug);
  }

  let user: User | null;
  let linkExternalId = false;
  const linked = externalId ? ctx.userByExternalId.get(externalId) : undefined;

  if (linked) {
    // A re-run is matched on the source's id, so an email that differs means the
    // source changed it. Moving an account to a new address is a takeover path, so
    // that stays an individual, deliberate change rather than a side effect.
    if (linked.email !== email) {
      return reject('email_mismatch');
    }
    user = linked;
  } else {
    user = ctx.userByEmail.get(email) ?? null;
    if (user && externalId) {
      const current = ctx.externalIdForUser.get(user.id);
      if (current && current !== externalId) {
        return reject('external_id_conflict');
      }
      // A linked external id becomes a way to sign in once a provider links imported
      // users by it, so tying an administrator's existing account to one is refused
      // here like granting an admin role is. Link an administrator individually.
      if (!current && (user.roles ?? []).some(isAdminRole)) {
        return reject('admin_role_not_allowed', 'existing account holds an admin role');
      }
      linkExternalId = !current;
    } else if (!user && externalId) {
      linkExternalId = true;
    }
  }

  const changes: UserImportChange[] = [];
  let phoneToSet: string | null = null;

  if (phone) {
    const owner = ctx.userByPhone.get(phone);
    if (owner && owner.id !== user?.id) {
      return reject('phone_in_use');
    }
    if (!user || !user.phone) {
      phoneToSet = phone;
    }
  }

  const memberships: MembershipPlan[] = [];
  for (const ref of orgRefs) {
    const organizationId = ctx.orgs.get(orgKey(ref))!;
    const existing = user ? (ctx.membership.get(`${user.id}:${organizationId}`) ?? null) : null;

    if (existing) {
      const addRoles = missingFrom(existing.roles, normalizeMembershipValues(ref.roles));
      const addScopes = missingFrom(existing.scopes, normalizeMembershipValues(ref.scopes));
      if (addRoles.length || addScopes.length) {
        memberships.push({
          organizationId,
          existing,
          roles: [...(existing.roles ?? []), ...addRoles],
          scopes: [...(existing.scopes ?? []), ...addScopes],
        });
      }
    } else {
      memberships.push({
        organizationId,
        existing: null,
        roles: normalizeOrganizationRoles(ref.roles),
        scopes: normalizeMembershipValues(ref.scopes),
      });
    }
  }

  let finalRoles: string[];
  if (user) {
    const added = missingFrom(user.roles, roles);
    finalRoles = [...(user.roles ?? []), ...added];
    if (linkExternalId) changes.push('linked');
    if (phoneToSet) changes.push('phone');
    if (added.length) changes.push('roles');
  } else {
    finalRoles = dedupe([...ctx.defaultRoles, ...roles]);
    changes.push('created');
  }
  if (memberships.length) changes.push('organizations');

  return {
    kind: 'apply',
    index,
    email,
    ...(externalId ? { externalId } : {}),
    user,
    roles: finalRoles,
    phone: phoneToSet,
    linkExternalId,
    memberships,
    changes,
  };
}

async function applyRow(plan: ApplyPlan, source: string): Promise<string> {
  return User.sequelize!.transaction(async (transaction: Transaction) => {
    let user = plan.user;

    if (!user) {
      user = await User.create(
        { email: plan.email, phone: plan.phone, roles: plan.roles },
        { transaction },
      );
    } else if (plan.changes.includes('roles') || plan.changes.includes('phone')) {
      await User.update(
        { roles: plan.roles, ...(plan.phone ? { phone: plan.phone } : {}) },
        { where: { id: user.id }, transaction },
      );
    }

    if (plan.linkExternalId && plan.externalId) {
      await UserExternalId.create(
        { userId: user.id, source, externalId: plan.externalId },
        { transaction },
      );
    }

    for (const membership of plan.memberships) {
      if (membership.existing) {
        await OrganizationMembership.update(
          { roles: membership.roles, scopes: membership.scopes },
          { where: { id: membership.existing.id }, transaction },
        );
      } else {
        await OrganizationMembership.create(
          {
            organizationId: membership.organizationId,
            userId: user.id,
            roles: membership.roles,
            scopes: membership.scopes,
          },
          { transaction },
        );
      }
    }

    return user.id;
  });
}

function toResult(plan: RowPlan, userId?: string): UserImportResult {
  const base = {
    index: plan.index,
    email: plan.email,
    ...(plan.externalId ? { externalId: plan.externalId } : {}),
  };

  if (plan.kind === 'reject') {
    return {
      ...base,
      status: 'rejected',
      reason: plan.reason,
      ...(plan.detail ? { detail: plan.detail } : {}),
    };
  }

  const status = plan.changes.includes('created')
    ? 'created'
    : plan.changes.length
      ? 'updated'
      : 'unchanged';

  return {
    ...base,
    status,
    ...(userId ? { userId } : {}),
    ...(plan.changes.length ? { changes: plan.changes } : {}),
  };
}

/**
 * Plans every row against the current data, then (unless this is a dry run) applies
 * each row in its own transaction. The plan is computed from reads alone, which is
 * what makes a dry run report exactly what a real run would do against the same data.
 * A row that loses a race between planning and writing, such as a concurrent signup
 * with the same address, is rejected on its own and does not stop the batch.
 */
export async function importUsers(request: ImportUsersRequest): Promise<ImportUsersResponse> {
  const ctx = await loadContext(request);
  const seen = {
    emails: new Set<string>(),
    externalIds: new Set<string>(),
    phones: new Set<string>(),
  };
  const plans = request.users.map((row, index) => planRow(row, index, ctx, seen));

  const results: UserImportResult[] = [];

  for (const plan of plans) {
    if (plan.kind === 'reject' || request.dryRun || !plan.changes.length) {
      results.push(toResult(plan, plan.kind === 'apply' ? plan.user?.id : undefined));
      continue;
    }

    try {
      const userId = await applyRow(plan, request.source);
      results.push(toResult(plan, userId));
    } catch (err) {
      logger.error(`Import row ${plan.index} failed to write. Reason: ${err}`);
      results.push(
        toResult({
          kind: 'reject',
          index: plan.index,
          email: plan.email,
          externalId: plan.externalId,
          reason: 'write_failed',
        }),
      );
    }
  }

  const summary = { created: 0, updated: 0, unchanged: 0, rejected: 0 };
  for (const result of results) summary[result.status] += 1;

  return { source: request.source, dryRun: request.dryRun, summary, results };
}
