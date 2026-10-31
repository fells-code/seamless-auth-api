/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type {
  OidcApplicationResource,
  OidcApplicationResourcesRequest,
  OidcResource as OidcResourceView,
  OidcResourceCreateRequest,
  OidcResourceUpdateRequest,
} from '@seamless-auth/types';
import { Op, UniqueConstraintError } from 'sequelize';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { OidcClientResource } from '../models/oidcClientResources.js';
import { OidcResource } from '../models/oidcResources.js';
import { findOidcApplication } from './oidcApplicationService.js';

export class OidcResourceError extends Error {
  constructor(
    readonly status: 400 | 404 | 409,
    message: string,
  ) {
    super(message);
  }
}

function withoutTrailingSlashes(value: string) {
  let end = value.length;
  while (end > 0 && value[end - 1] === '/') end--;
  return value.slice(0, end);
}

export function serializeOidcResource(resource: OidcResource): OidcResourceView {
  return {
    id: resource.id,
    identifier: resource.identifier,
    name: resource.name,
    scopes: resource.scopes,
    accessTokenTtlSeconds: resource.accessTokenTtlSeconds ?? null,
    createdAt: new Date(resource.createdAt).toISOString(),
    updatedAt: new Date(resource.updatedAt).toISOString(),
  };
}

/**
 * A provider access token's `aud` is the resource, so a resource named after the API's
 * `ISSUER` or the provider's own issuer would mint tokens that claim to be for either
 * (ADR 0001, D5 and D11). `/oidc/sign` refuses those audiences too.
 */
async function assertIdentifierAllowed(identifier: string) {
  const { oidc_issuer } = await getSystemConfig();
  const reserved = [process.env.ISSUER, oidc_issuer]
    .filter((value): value is string => Boolean(value))
    .map(withoutTrailingSlashes);

  if (reserved.includes(withoutTrailingSlashes(identifier))) {
    throw new OidcResourceError(400, 'A resource cannot use the API or provider issuer');
  }
}

export async function listOidcResources() {
  return OidcResource.findAll({ order: [['createdAt', 'ASC']] });
}

export async function findOidcResource(id: string) {
  const resource = await OidcResource.findByPk(id);
  if (!resource) throw new OidcResourceError(404, 'Resource not found');
  return resource;
}

export async function createOidcResource(input: OidcResourceCreateRequest) {
  await assertIdentifierAllowed(input.identifier);

  try {
    return await OidcResource.create({
      identifier: input.identifier,
      name: input.name,
      scopes: input.scopes,
      accessTokenTtlSeconds: input.accessTokenTtlSeconds ?? null,
    });
  } catch (error) {
    if (error instanceof UniqueConstraintError) {
      throw new OidcResourceError(409, 'A resource with that identifier already exists');
    }
    throw error;
  }
}

/** A scope removed from the resource is removed from every application allowed it. */
export async function updateOidcResource(id: string, patch: OidcResourceUpdateRequest) {
  const resource = await findOidcResource(id);

  await OidcResource.sequelize!.transaction(async (transaction) => {
    await resource.update(patch, { transaction });

    if (!patch.scopes) return;

    const kept = new Set(patch.scopes);
    const links = await OidcClientResource.findAll({ where: { resourceId: id }, transaction });

    for (const link of links) {
      const scopes = link.scopes.filter((scope) => kept.has(scope));
      if (scopes.length !== link.scopes.length) await link.update({ scopes }, { transaction });
    }
  });

  return resource;
}

export async function deleteOidcResource(id: string) {
  const resource = await findOidcResource(id);

  await OidcResource.sequelize!.transaction(async (transaction) => {
    await OidcClientResource.destroy({ where: { resourceId: id }, transaction });
    await resource.destroy({ transaction });
  });
}

export async function listOidcApplicationResources(
  clientId: string,
): Promise<OidcApplicationResource[]> {
  await findOidcApplication(clientId);

  const links = await OidcClientResource.findAll({ where: { clientId } });
  if (links.length === 0) return [];

  const resources = await OidcResource.findAll({
    where: { id: { [Op.in]: links.map((link) => link.resourceId) } },
    order: [['createdAt', 'ASC']],
  });
  const scopesById = new Map(links.map((link) => [link.resourceId, link.scopes]));

  return resources.map((resource) => ({
    resourceId: resource.id,
    identifier: resource.identifier,
    name: resource.name,
    scopes: (scopesById.get(resource.id) ?? []).filter((scope) => resource.scopes.includes(scope)),
  }));
}

/**
 * Replaces the resources an application may request tokens for. Each scope must be one
 * the resource declares, so an application can never be allowed more than the API offers.
 */
export async function setOidcApplicationResources(
  clientId: string,
  { resources: grants }: OidcApplicationResourcesRequest,
) {
  await findOidcApplication(clientId);

  const resources = grants.length
    ? await OidcResource.findAll({
        where: { id: { [Op.in]: grants.map((grant) => grant.resourceId) } },
      })
    : [];
  const byId = new Map(resources.map((resource) => [resource.id, resource]));

  for (const grant of grants) {
    const resource = byId.get(grant.resourceId);
    if (!resource) throw new OidcResourceError(400, `Unknown resource ${grant.resourceId}`);

    const undeclared = grant.scopes.filter((scope) => !resource.scopes.includes(scope));
    if (undeclared.length > 0) {
      throw new OidcResourceError(
        400,
        `${resource.identifier} does not declare ${undeclared.join(', ')}`,
      );
    }
  }

  await OidcClientResource.sequelize!.transaction(async (transaction) => {
    await OidcClientResource.destroy({ where: { clientId }, transaction });
    if (grants.length === 0) return;
    await OidcClientResource.bulkCreate(
      grants.map((grant) => ({ clientId, resourceId: grant.resourceId, scopes: grant.scopes })),
      { transaction },
    );
  });

  return listOidcApplicationResources(clientId);
}
