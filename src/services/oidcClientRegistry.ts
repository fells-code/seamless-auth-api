/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  APPLICATION_NOTICE_SCOPE,
  type OidcAccountClaims,
  type OidcClientMetadata,
  type OidcPublicJwk,
  oidcRedirectUriKind,
  seamlessBuiltInResource,
} from '@seamless-auth/types';
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
const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

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

/** A loopback or private-use redirect (RFC 8252) makes the client a native one. */
export function isNativeRedirectUri(uri: string) {
  const kind = oidcRedirectUriKind(uri);
  return kind === 'loopback' || kind === 'private_use';
}

export async function getOidcClientMetadata(id: string): Promise<OidcClientMetadata | null> {
  const client = await findActiveOidcClient(id);

  if (!client) return null;

  return {
    client_id: client.id,
    client_name: client.name,
    application_type: client.redirectUris.some(isNativeRedirectUri) ? 'native' : 'web',
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    // The device grant only for a first-party client with the flag on (ADR 0001, D10),
    // whatever the stored grant list says.
    grant_types: client.grantTypes.filter(
      (grant) => grant !== DEVICE_CODE_GRANT || (client.firstParty && client.deviceFlowEnabled),
    ) as OidcClientMetadata['grant_types'],
    response_types: client.grantTypes.includes('authorization_code') ? ['code'] : [],
    redirect_uris: client.redirectUris,
    post_logout_redirect_uris: client.postLogoutRedirectUris,
    ...(client.jwks ? { jwks: client.jwks as { keys: OidcPublicJwk[] } } : {}),
    ...(client.jwksUri ? { jwks_uri: client.jwksUri } : {}),
    // Logout tokens always carry sid, so the ID token must too for the RP to match them.
    ...(client.backchannelLogoutUri
      ? {
          backchannel_logout_uri: client.backchannelLogoutUri,
          backchannel_logout_session_required: true,
        }
      : {}),
    'urn:seamless:first_party': client.firstParty,
    ...(client.accessTokenTtlSeconds
      ? { 'urn:seamless:access_token_ttl': client.accessTokenTtlSeconds }
      : {}),
    ...(client.idTokenTtlSeconds ? { 'urn:seamless:id_token_ttl': client.idTokenTtlSeconds } : {}),
    ...(client.refreshTokenTtlSeconds
      ? { 'urn:seamless:refresh_token_ttl': client.refreshTokenTtlSeconds }
      : {}),
    ...(client.pkceRequired === false && client.clientType === 'confidential'
      ? {
          'urn:seamless:pkce_required': false,
          ...(client.nonceRequired === false ? { 'urn:seamless:nonce_required': false } : {}),
        }
      : {}),
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

/**
 * The resources a client may ask an access token for, each with the scopes it is allowed
 * there. A link may only narrow what the resource defines, whatever was stored on it. The
 * built-in `<oidc_issuer>/seamless` resource is never stored: an admin turning notices on
 * for the client is what links it (ADR 0001, D14).
 */
export async function getOidcClientResources(clientId: string) {
  const client = await findActiveOidcClient(clientId);
  const { oidc_issuer } = await getSystemConfig();
  const builtIn = oidc_issuer ? seamlessBuiltInResource(oidc_issuer) : null;
  const resources: {
    identifier: string;
    scopes: string[];
    accessTokenTtlSeconds: number | null;
  }[] =
    builtIn && client?.noticesEnabled
      ? [{ identifier: builtIn, scopes: [APPLICATION_NOTICE_SCOPE], accessTokenTtlSeconds: null }]
      : [];

  const links = await OidcClientResource.findAll({ where: { clientId } });

  if (links.length === 0) return resources;

  const stored = await OidcResource.findAll({
    where: { id: { [Op.in]: links.map((link) => link.resourceId) } },
  });
  const byId = new Map(stored.map((resource) => [resource.id, resource]));

  for (const link of links) {
    const resource = byId.get(link.resourceId);
    if (!resource || resource.identifier === builtIn) continue;
    resources.push({
      identifier: resource.identifier,
      scopes: link.scopes.filter((scope) => resource.scopes.includes(scope)),
      accessTokenTtlSeconds: resource.accessTokenTtlSeconds ?? null,
    });
  }

  return resources;
}

/** The scopes a client may request at each resource it is linked to, keyed by identifier. */
export async function getOidcClientResourceScopes(clientId: string) {
  const resources = await getOidcClientResources(clientId);
  return new Map(resources.map((resource) => [resource.identifier, new Set(resource.scopes)]));
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
