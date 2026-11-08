/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { Transaction } from 'sequelize';

import { type AuthorizationClaims, signAccessToken } from '../lib/token.js';
import { OrganizationMembership } from '../models/organizationMemberships.js';
import { Session } from '../models/sessions.js';
import { AuthEventService } from './authEventService.js';
import { resolveCustomClaims } from './customClaimService.js';
import { findMembership } from './organizationService.js';
import { permissionsForRoles } from './permissionService.js';

/**
 * How much of an access token its authorization claims may take together, serialized: the
 * permission claims (`permissions`, `org_roles`, `org_permissions`) and the custom claims
 * (ADR 0004 P4, ADR 0005 E6). A server adapter keeps the whole token inside a signed cookie, so
 * it is base64 encoded twice under the browser's 4 KiB limit.
 * `tests/unit/services/accessTokenService.spec.ts` builds that cookie at this budget and holds
 * it under the limit. Each custom claim set is separately held to `CUSTOM_CLAIMS_BUDGET_BYTES`
 * when written.
 */
export const AUTHORIZATION_CLAIMS_BUDGET_BYTES = 1024;

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

export type BudgetedClaims = {
  authorization: AuthorizationClaims;
  customClaims: Record<string, unknown>;
  /** Set when the custom claims had to go, with the size that did not fit. */
  customClaimsOmitted: { bytes: number } | null;
};

function serializedBytes(claims: Record<string, unknown>) {
  return Buffer.byteLength(JSON.stringify(claims));
}

/**
 * One budget for every authorization claim, each set kept whole or not at all, since a partial
 * list looks complete and denies silently. Permissions give way first: a guard that sees
 * `permissions_omitted` reads `GET /users/me/permissions`, and custom claims have no such
 * fallback. Custom claims go only when they do not fit even beside the marker.
 */
export function authorizationClaims(
  {
    permissions,
    organizationId,
    organizationRoles,
    organizationPermissions,
  }: ResolvedAuthorization,
  customClaims: Record<string, unknown> = {},
): BudgetedClaims {
  const permissionClaims = {
    permissions,
    ...(organizationId
      ? { org_roles: organizationRoles, org_permissions: organizationPermissions }
      : {}),
  };

  if (
    serializedBytes({ ...customClaims, ...permissionClaims }) <= AUTHORIZATION_CLAIMS_BUDGET_BYTES
  ) {
    return { authorization: permissionClaims, customClaims, customClaimsOmitted: null };
  }

  const marker = { permissions_omitted: true } as const;
  const withMarker = serializedBytes({ ...customClaims, ...marker });

  if (withMarker <= AUTHORIZATION_CLAIMS_BUDGET_BYTES) {
    return { authorization: marker, customClaims, customClaimsOmitted: null };
  }

  return { authorization: marker, customClaims: {}, customClaimsOmitted: { bytes: withMarker } };
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

  const budgeted = authorizationClaims(
    authorization,
    recovery
      ? {}
      : await resolveCustomClaims({
          roles: user.roles ?? [],
          organizationRoles: authorization.organizationRoles,
          hookClaims: leftOrganization ? null : session.hookClaims,
          transaction,
        }),
  );

  if (budgeted.customClaimsOmitted) {
    await AuthEventService.logContext({
      userId: user.id,
      sessionId: session.id,
      type: 'custom_claims_omitted',
      metadata: {
        bytes: budgeted.customClaimsOmitted.bytes,
        budgetBytes: AUTHORIZATION_CLAIMS_BUDGET_BYTES,
      },
    });
  }

  const token = await signAccessToken(
    session.id,
    user.id,
    user.roles ?? [],
    authorization.organizationId,
    { recovery, authorization: budgeted.authorization, customClaims: budgeted.customClaims },
  );

  return {
    token,
    organizationId: recovery ? (session.organizationId ?? null) : authorization.organizationId,
  };
}
