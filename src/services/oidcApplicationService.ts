/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  type OidcApplication,
  type OidcApplicationCreateRequest,
  OidcApplicationCreateRequestSchema,
  type OidcApplicationGrantType,
  OidcApplicationGrantTypeSchema,
  type OidcApplicationKeysRequest,
  type OidcApplicationUpdateRequest,
} from '@seamless-auth/types';
import { randomBytes } from 'crypto';
import type { ZodError } from 'zod';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { OidcClientResource } from '../models/oidcClientResources.js';
import { OidcClient, type OidcClientAuthMethod } from '../models/oidcClients.js';
import { OidcPayload } from '../models/oidcPayloads.js';
import { createOidcClientSecretLookup, isNativeRedirectUri } from './oidcClientRegistry.js';

export const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

const SHARED_SECRET_METHODS = new Set<OidcClientAuthMethod>([
  'client_secret_basic',
  'client_secret_post',
]);

export class OidcApplicationError extends Error {
  constructor(
    readonly status: 400 | 404,
    message: string,
  ) {
    super(message);
  }
}

export class OidcApplicationInvalidError extends Error {
  constructor(readonly zodError: ZodError) {
    super('application settings are invalid');
  }
}

const INPUT_GRANTS = new Set<string>(OidcApplicationGrantTypeSchema.options);

export function serializeOidcApplication(client: OidcClient): OidcApplication {
  return {
    id: client.id,
    name: client.name,
    clientType: client.clientType,
    applicationType: client.redirectUris.some(isNativeRedirectUri) ? 'native' : 'web',
    firstParty: client.firstParty,
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    redirectUris: client.redirectUris,
    postLogoutRedirectUris: client.postLogoutRedirectUris,
    grantTypes: client.grantTypes.filter((grant): grant is OidcApplicationGrantType =>
      INPUT_GRANTS.has(grant),
    ),
    deviceFlowEnabled: client.deviceFlowEnabled,
    noticesEnabled: client.noticesEnabled,
    jwks: (client.jwks as OidcApplication['jwks']) ?? null,
    jwksUri: client.jwksUri ?? null,
    hasSecret: Boolean(client.secretLookup),
    backchannelLogoutUri: client.backchannelLogoutUri ?? null,
    accessTokenTtlSeconds: client.accessTokenTtlSeconds ?? null,
    idTokenTtlSeconds: client.idTokenTtlSeconds ?? null,
    refreshTokenTtlSeconds: client.refreshTokenTtlSeconds ?? null,
    disabled: Boolean(client.disabledAt),
    createdAt: new Date(client.createdAt).toISOString(),
    updatedAt: new Date(client.updatedAt).toISOString(),
  };
}

function storedGrantTypes(grants: string[], deviceFlowEnabled: boolean) {
  return deviceFlowEnabled ? [...grants, DEVICE_CODE_GRANT] : grants;
}

/**
 * ADR 0001, D6 and D10. The schema cannot see instance config, so these are checked
 * here, and only for settings the request names: an instance that later turns a flag off
 * does not lock every existing client out of being renamed. The edge enforces both flags
 * at sign-in either way.
 */
async function assertInstanceAllows(settings: {
  firstParty?: boolean | undefined;
  tokenEndpointAuthMethod?: OidcClientAuthMethod | undefined;
}) {
  const config = await getSystemConfig();

  if (
    settings.tokenEndpointAuthMethod &&
    SHARED_SECRET_METHODS.has(settings.tokenEndpointAuthMethod) &&
    !config.allow_client_secrets
  ) {
    throw new OidcApplicationError(
      400,
      'Shared client secrets are off on this instance (allow_client_secrets)',
    );
  }

  if (settings.firstParty === false && !config.third_party_clients_enabled) {
    throw new OidcApplicationError(
      400,
      'Third-party clients are off on this instance (third_party_clients_enabled). Mark the application first-party, or enable third-party clients.',
    );
  }
}

function newSecret() {
  const secret = randomBytes(32).toString('base64url');
  return { secret, lookup: createOidcClientSecretLookup(secret) };
}

export async function listOidcApplications() {
  return OidcClient.findAll({ order: [['createdAt', 'ASC']] });
}

export async function findOidcApplication(id: string) {
  const client = await OidcClient.findByPk(id);
  if (!client) throw new OidcApplicationError(404, 'Application not found');
  return client;
}

export async function createOidcApplication(input: OidcApplicationCreateRequest) {
  const tokenEndpointAuthMethod =
    input.tokenEndpointAuthMethod ??
    (input.clientType === 'public' ? ('none' as const) : ('private_key_jwt' as const));

  await assertInstanceAllows({ firstParty: input.firstParty, tokenEndpointAuthMethod });

  const issued = SHARED_SECRET_METHODS.has(tokenEndpointAuthMethod) ? newSecret() : null;

  const client = await OidcClient.create({
    id: randomBytes(16).toString('base64url'),
    name: input.name,
    clientType: input.clientType,
    firstParty: input.firstParty,
    tokenEndpointAuthMethod,
    jwks: input.jwks ?? null,
    jwksUri: input.jwksUri ?? null,
    secretLookup: issued?.lookup ?? null,
    redirectUris: input.redirectUris,
    postLogoutRedirectUris: input.postLogoutRedirectUris,
    grantTypes: storedGrantTypes(input.grantTypes, input.deviceFlowEnabled),
    backchannelLogoutUri: input.backchannelLogoutUri ?? null,
    accessTokenTtlSeconds: input.accessTokenTtlSeconds ?? null,
    idTokenTtlSeconds: input.idTokenTtlSeconds ?? null,
    refreshTokenTtlSeconds: input.refreshTokenTtlSeconds ?? null,
    deviceFlowEnabled: input.deviceFlowEnabled,
    noticesEnabled: input.noticesEnabled,
  });

  return { client, clientSecret: issued?.secret };
}

/**
 * Applies a partial update and re-runs every create rule on the merged result. Leaving
 * `private_key_jwt` drops the registered keys, and leaving a shared-secret method drops
 * the secret, so neither lingers on a client that no longer uses it.
 */
export async function updateOidcApplication(id: string, patch: OidcApplicationUpdateRequest) {
  const client = await findOidcApplication(id);
  const { disabled, ...settings } = patch;

  await assertInstanceAllows(settings);

  const current = serializeOidcApplication(client);
  const method = settings.tokenEndpointAuthMethod ?? client.tokenEndpointAuthMethod;
  const keepsKeys = method === 'private_key_jwt';

  const merged = {
    name: current.name,
    clientType: current.clientType,
    firstParty: current.firstParty,
    tokenEndpointAuthMethod: current.tokenEndpointAuthMethod,
    redirectUris: current.redirectUris,
    postLogoutRedirectUris: current.postLogoutRedirectUris,
    grantTypes: current.grantTypes,
    deviceFlowEnabled: current.deviceFlowEnabled,
    noticesEnabled: current.noticesEnabled,
    backchannelLogoutUri: current.backchannelLogoutUri,
    accessTokenTtlSeconds: current.accessTokenTtlSeconds,
    idTokenTtlSeconds: current.idTokenTtlSeconds,
    refreshTokenTtlSeconds: current.refreshTokenTtlSeconds,
    ...settings,
    ...(keepsKeys && current.jwks ? { jwks: current.jwks } : {}),
    ...(keepsKeys && current.jwksUri ? { jwksUri: current.jwksUri } : {}),
  };

  const parsed = OidcApplicationCreateRequestSchema.safeParse(merged);
  if (!parsed.success) throw new OidcApplicationInvalidError(parsed.error);

  const next = parsed.data;

  await client.update({
    name: next.name,
    firstParty: next.firstParty,
    tokenEndpointAuthMethod: method,
    redirectUris: next.redirectUris,
    postLogoutRedirectUris: next.postLogoutRedirectUris,
    grantTypes: storedGrantTypes(next.grantTypes, next.deviceFlowEnabled),
    deviceFlowEnabled: next.deviceFlowEnabled,
    noticesEnabled: next.noticesEnabled,
    backchannelLogoutUri: next.backchannelLogoutUri ?? null,
    accessTokenTtlSeconds: next.accessTokenTtlSeconds ?? null,
    idTokenTtlSeconds: next.idTokenTtlSeconds ?? null,
    refreshTokenTtlSeconds: next.refreshTokenTtlSeconds ?? null,
    ...(keepsKeys ? {} : { jwks: null, jwksUri: null }),
    ...(SHARED_SECRET_METHODS.has(method) ? {} : { secretLookup: null }),
    ...(disabled === undefined
      ? {}
      : { disabledAt: disabled ? (client.disabledAt ?? new Date()) : null }),
  });

  return client;
}

export async function setOidcApplicationKeys(id: string, keys: OidcApplicationKeysRequest) {
  const client = await findOidcApplication(id);

  if (client.tokenEndpointAuthMethod !== 'private_key_jwt') {
    throw new OidcApplicationError(400, 'Keys are only used by private_key_jwt applications');
  }

  await client.update(
    'jwks' in keys ? { jwks: keys.jwks, jwksUri: null } : { jwks: null, jwksUri: keys.jwksUri },
  );

  return client;
}

/** Issues a shared secret, replacing any previous one at once. Returned here and never again. */
export async function rotateOidcApplicationSecret(id: string) {
  const client = await findOidcApplication(id);

  if (!SHARED_SECRET_METHODS.has(client.tokenEndpointAuthMethod)) {
    throw new OidcApplicationError(
      400,
      'Only applications using client_secret_basic or client_secret_post have a secret',
    );
  }

  await assertInstanceAllows({ tokenEndpointAuthMethod: client.tokenEndpointAuthMethod });

  const { secret, lookup } = newSecret();
  await client.update({ secretLookup: lookup });

  return { client, clientSecret: secret };
}

/**
 * Deletes the application with its resource grants and every provider record issued to
 * it (grants, codes and tokens), so nothing it was given outlives it.
 */
export async function deleteOidcApplication(id: string) {
  const client = await findOidcApplication(id);

  await OidcClient.sequelize!.transaction(async (transaction) => {
    await OidcPayload.destroy({ where: { payload: { clientId: id } }, transaction });
    await OidcClientResource.destroy({ where: { clientId: id }, transaction });
    await client.destroy({ transaction });
  });
}
