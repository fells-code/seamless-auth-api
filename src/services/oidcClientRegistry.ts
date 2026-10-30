/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { OidcAccountClaims, OidcClientMetadata, OidcPublicJwk } from '@seamless-auth/types';
import { createHmac, timingSafeEqual } from 'crypto';
import { Op } from 'sequelize';

import { authSecret } from '../config/authSecrets.js';
import { getSystemConfig } from '../config/getSystemConfig.js';
import { OidcClientResource } from '../models/oidcClientResources.js';
import { OidcClient } from '../models/oidcClients.js';
import { OidcResource } from '../models/oidcResources.js';
import { User } from '../models/users.js';
import { isUuid } from './oidcAuthContext.js';
import { getDefaultOrganizationIdForUser } from './organizationService.js';

const SHARED_SECRET_METHODS = new Set(['client_secret_basic', 'client_secret_post']);

/**
 * Keyed with the refresh token lookup secret, but over a prefixed input, so a client
 * secret's lookup can never collide with a refresh token's.
 */
export function createOidcClientSecretLookup(secret: string) {
  return createHmac('sha256', authSecret('REFRESH_TOKEN_LOOKUP_SECRET'))
    .update(`oidc-client-secret:${secret}`)
    .digest('hex');
}

export async function findActiveOidcClient(id: string) {
  const client = await OidcClient.findByPk(id);

  return client && !client.disabledAt ? client : null;
}

function isNativeRedirect(uri: string) {
  const { protocol, hostname } = new URL(uri);

  return (
    (protocol !== 'https:' && protocol !== 'http:') ||
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]'
  );
}

export async function getOidcClientMetadata(id: string): Promise<OidcClientMetadata | null> {
  const client = await findActiveOidcClient(id);

  if (!client) return null;

  return {
    client_id: client.id,
    client_name: client.name,
    application_type: client.redirectUris.some(isNativeRedirect) ? 'native' : 'web',
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    grant_types: client.grantTypes as OidcClientMetadata['grant_types'],
    response_types: client.grantTypes.includes('authorization_code') ? ['code'] : [],
    redirect_uris: client.redirectUris,
    post_logout_redirect_uris: client.postLogoutRedirectUris,
    ...(client.jwks ? { jwks: client.jwks as { keys: OidcPublicJwk[] } } : {}),
    ...(client.jwksUri ? { jwks_uri: client.jwksUri } : {}),
    ...(client.backchannelLogoutUri ? { backchannel_logout_uri: client.backchannelLogoutUri } : {}),
    'urn:seamless:first_party': client.firstParty,
  };
}

/**
 * True only for an active client opted in to a shared secret, on an instance that allows
 * them, presenting the secret whose lookup is stored. Every other case is false, so the
 * edge cannot tell a wrong secret from a client that has none.
 */
export async function verifyOidcClientSecret(id: string, secret: string) {
  const { allow_client_secrets } = await getSystemConfig();
  const client = await findActiveOidcClient(id);

  if (
    !allow_client_secrets ||
    !client?.secretLookup ||
    !SHARED_SECRET_METHODS.has(client.tokenEndpointAuthMethod)
  ) {
    return false;
  }

  const presented = Buffer.from(createOidcClientSecretLookup(secret), 'hex');
  const stored = Buffer.from(client.secretLookup, 'hex');

  return presented.length === stored.length && timingSafeEqual(presented, stored);
}

/** The scopes a client may request at each resource it is linked to, keyed by identifier. */
export async function getOidcClientResourceScopes(clientId: string) {
  const links = await OidcClientResource.findAll({ where: { clientId } });

  if (links.length === 0) return new Map<string, Set<string>>();

  const resources = await OidcResource.findAll({
    where: { id: { [Op.in]: links.map((link) => link.resourceId) } },
  });
  const byId = new Map(resources.map((resource) => [resource.id, resource]));
  const scopes = new Map<string, Set<string>>();

  for (const link of links) {
    const resource = byId.get(link.resourceId);
    if (!resource) continue;

    // A link may only narrow what the resource defines, whatever was stored on it.
    scopes.set(
      resource.identifier,
      new Set(link.scopes.filter((scope) => resource.scopes.includes(scope))),
    );
  }

  return scopes;
}

export async function getOidcAccountClaims(userId: string): Promise<OidcAccountClaims | null> {
  if (!isUuid(userId)) return null;

  const user = await User.findOne({ where: { id: userId } });

  if (!user || user.revoked) return null;

  return {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified === true,
    ...(user.phone
      ? { phone_number: user.phone, phone_number_verified: user.phoneVerified === true }
      : {}),
    roles: user.roles ?? [],
    org_id: await getDefaultOrganizationIdForUser(user.id),
  };
}
