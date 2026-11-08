/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { type CustomClaimSourceKind, isReservedClaimName } from '@seamless-auth/types';
import { Op, type Transaction } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { CustomClaim } from '../models/customClaims.js';
import { OidcClient } from '../models/oidcClients.js';
import { OrganizationRole } from '../models/organizationRoles.js';

export class CustomClaimError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'CustomClaimError';
  }
}

export type ClaimSet = Record<string, unknown>;

export function serializeCustomClaimSource(source: CustomClaim) {
  return {
    sourceKind: source.sourceKind,
    sourceName: source.sourceName,
    claims: source.claims ?? {},
    updatedAt: source.updatedAt.toISOString(),
  };
}

export async function listCustomClaimSources() {
  return CustomClaim.findAll({
    order: [
      ['sourceKind', 'ASC'],
      ['sourceName', 'ASC'],
    ],
  });
}

export async function getCustomClaimSource(sourceKind: CustomClaimSourceKind, sourceName: string) {
  const source = await CustomClaim.findOne({ where: { sourceKind, sourceName } });
  if (!source) throw new CustomClaimError(404, 'Custom claims not found');
  return source;
}

async function sourceExists(sourceKind: CustomClaimSourceKind, sourceName: string) {
  switch (sourceKind) {
    case 'instance_role':
      return ((await getSystemConfig()).available_roles ?? []).includes(sourceName);
    case 'organization_role':
      return Boolean(await OrganizationRole.findByPk(sourceName));
    case 'oidc_client':
      return Boolean(await OidcClient.findByPk(sourceName));
  }
}

/**
 * Replaces the source's whole set. The request schema has already refused reserved names, deep
 * values and a set over the budget. The source must exist, so a typo is not stored as claims
 * nothing will ever carry.
 */
export async function setCustomClaimSource(
  sourceKind: CustomClaimSourceKind,
  sourceName: string,
  claims: ClaimSet,
) {
  if (!(await sourceExists(sourceKind, sourceName))) {
    throw new CustomClaimError(404, 'Source not found');
  }

  const existing = await CustomClaim.findOne({ where: { sourceKind, sourceName } });
  const previous = existing ? Object.keys(existing.claims ?? {}) : [];

  if (existing) {
    // A new object, so Sequelize sees the JSONB change.
    await existing.update({ claims: { ...claims } });
    return { source: existing, previous };
  }

  const source = await CustomClaim.create({ sourceKind, sourceName, claims });
  return { source, previous };
}

export async function deleteCustomClaimSource(
  sourceKind: CustomClaimSourceKind,
  sourceName: string,
) {
  const source = await getCustomClaimSource(sourceKind, sourceName);
  await source.destroy();
  return source;
}

/** For a role or client leaving the instance, so adding the name back cannot restore old claims. */
export async function deleteCustomClaimsFor(
  sourceKind: CustomClaimSourceKind,
  names: string[],
  transaction?: Transaction,
) {
  if (names.length === 0) return 0;
  return CustomClaim.destroy({
    where: { sourceKind, sourceName: { [Op.in]: names } },
    transaction,
  });
}

function setsFor(rows: CustomClaim[], kind: CustomClaimSourceKind, names: string[]) {
  return [...new Set(names)]
    .sort()
    .map((name) => rows.find((row) => row.sourceKind === kind && row.sourceName === name))
    .filter((row): row is CustomClaim => row !== undefined)
    .map((row) => row.claims ?? {});
}

/**
 * Instance role sets, then organization role sets (only while the membership exists), then the
 * session's hook claims. A later source wins per name, and roles of one kind apply in name order,
 * so the result does not depend on the order roles were granted in. Reserved names are filtered
 * again here, whatever was stored. The token budget is applied by `authorizationClaims`.
 */
export async function resolveCustomClaims({
  roles,
  organizationRoles,
  hookClaims,
  transaction,
}: {
  roles: string[];
  organizationRoles: string[];
  hookClaims: ClaimSet | null | undefined;
  transaction?: Transaction;
}): Promise<ClaimSet> {
  const wanted = [
    ...(roles.length ? [{ sourceKind: 'instance_role', sourceName: { [Op.in]: roles } }] : []),
    ...(organizationRoles.length
      ? [{ sourceKind: 'organization_role', sourceName: { [Op.in]: organizationRoles } }]
      : []),
  ];
  const rows = wanted.length
    ? await CustomClaim.findAll({ where: { [Op.or]: wanted }, transaction })
    : [];

  const merged: ClaimSet = {};
  for (const set of [
    ...setsFor(rows, 'instance_role', roles),
    ...setsFor(rows, 'organization_role', organizationRoles),
    hookClaims ?? {},
  ]) {
    for (const [name, value] of Object.entries(set)) {
      if (!isReservedClaimName(name)) merged[name] = value;
    }
  }

  return merged;
}
