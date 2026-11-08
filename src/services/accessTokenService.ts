/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { CUSTOM_CLAIMS_BUDGET_BYTES } from '@seamless-auth/types';
import type { Transaction } from 'sequelize';

import { type AuthorizationClaims, signAccessToken } from '../lib/token.js';
import { OrganizationMembership } from '../models/organizationMemberships.js';
import { Session } from '../models/sessions.js';
import { AuthEventService } from './authEventService.js';
import { resolveCustomClaims } from './customClaimService.js';
import { findMembership } from './organizationService.js';
import { permissionsForRoles } from './permissionService.js';

/**
 * How much of an access token the organization roles and permission arrays may take,
 * serialized. A server adapter keeps the whole token inside a signed cookie, so it is base64
 * encoded twice under the browser's 4 KiB limit. `tests/unit/services/accessTokenService.spec.ts`
 * builds that cookie at this budget and holds it under the limit.
 */
export const PERMISSION_CLAIMS_BUDGET_BYTES = 1024;

type AuthorizationInput = {
  userId: string;
  roles: string[] | null | undefined;
  organizationId?: string | null;
  recovery: boolean;
  /** The membership, when the caller has just read it. Otherwise it is read here. */
  membership?: OrganizationMembership | null;
  transaction?: Transaction;
};

export type ResolvedAuthorization = {
  roles: string[];
  permissions: string[];
  /** Null when there is no active organization, or the user no longer belongs to it. */
  organizationId: string | null;
  organizationRoles: string[];
  organizationPermissions: string[];
};

/**
 * What the user holds right now. The membership is read rather than trusted from the session,
 * so removal from an organization takes effect here, whatever the session row still says. A
 * recovery session can only enroll a new factor, so it holds nothing.
 */
export async function resolveAuthorization({
  userId,
  roles,
  organizationId,
  recovery,
  membership,
  transaction,
}: AuthorizationInput): Promise<ResolvedAuthorization> {
  const none = { organizationId: null, organizationRoles: [], organizationPermissions: [] };

  if (recovery) {
    return { roles: roles ?? [], permissions: [], ...none };
  }

  const permissions = await permissionsForRoles('instance', roles, transaction);
  const held =
    membership === undefined && organizationId
      ? await findMembership(userId, organizationId, transaction)
      : membership;

  if (!organizationId || !held) {
    return { roles: roles ?? [], permissions, ...none };
  }

  const organizationRoles = Array.isArray(held.roles) ? held.roles : [];

  return {
    roles: roles ?? [],
    permissions,
    organizationId,
    organizationRoles,
    organizationPermissions: await permissionsForRoles(
      'organization',
      organizationRoles,
      transaction,
    ),
  };
}

/**
 * All or nothing. A partial list looks complete and denies silently, so a set that does not
 * fit is replaced with a marker that sends a guard to `GET /users/me/permissions`.
 */
export function authorizationClaims({
  permissions,
  organizationId,
  organizationRoles,
  organizationPermissions,
}: ResolvedAuthorization): AuthorizationClaims {
  const claims = {
    permissions,
    ...(organizationId
      ? { org_roles: organizationRoles, org_permissions: organizationPermissions }
      : {}),
  };

  if (Buffer.byteLength(JSON.stringify(claims)) > PERMISSION_CLAIMS_BUDGET_BYTES) {
    return { permissions_omitted: true };
  }

  return claims;
}

/**
 * Every first-party access token is minted here, so sign-in, refresh, organization switch and
 * session exchange cannot disagree about what a token grants. Returns the organization the
 * token actually carries, for the response: a member who has been removed has none, and the
 * session stops naming it. A recovery token drops the claims but keeps the session's
 * organization, which applies again once a factor is enrolled.
 */
export async function mintAccessToken({
  session,
  user,
  membership,
  transaction,
}: {
  session: {
    id: string;
    organizationId?: string | null;
    recovery?: boolean | null;
    hookClaims?: Record<string, unknown> | null;
  };
  user: { id: string; roles?: string[] | null };
  membership?: OrganizationMembership | null;
  transaction?: Transaction;
}) {
  const recovery = session.recovery === true;
  const authorization = await resolveAuthorization({
    userId: user.id,
    roles: user.roles,
    organizationId: session.organizationId,
    recovery,
    membership,
    transaction,
  });

  const leftOrganization = Boolean(
    session.organizationId && !authorization.organizationId && !recovery,
  );

  // The hook's claims were decided for that organization, so they go with it.
  if (leftOrganization) {
    await Session.update(
      { organizationId: null, hookClaims: null },
      { where: { id: session.id }, transaction },
    );
  }

  const custom = recovery
    ? null
    : await resolveCustomClaims({
        roles: user.roles ?? [],
        organizationRoles: authorization.organizationRoles,
        hookClaims: leftOrganization ? null : session.hookClaims,
        transaction,
      });

  if (custom?.omitted) {
    await AuthEventService.logContext({
      userId: user.id,
      sessionId: session.id,
      type: 'custom_claims_omitted',
      metadata: { bytes: custom.bytes, budgetBytes: CUSTOM_CLAIMS_BUDGET_BYTES },
    });
  }
  const customClaims = custom?.claims ?? {};

  const token = await signAccessToken(
    session.id,
    user.id,
    user.roles ?? [],
    authorization.organizationId,
    { recovery, authorization: authorizationClaims(authorization), customClaims },
  );

  return {
    token,
    organizationId: recovery ? (session.organizationId ?? null) : authorization.organizationId,
  };
}
