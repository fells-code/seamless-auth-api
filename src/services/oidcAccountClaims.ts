/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { CustomClaimSet, OidcAccountClaims } from '@seamless-auth/types';

import type { AuthorizationClaims } from '../lib/token.js';
import { User } from '../models/users.js';
import {
  AUTHORIZATION_CLAIMS_BUDGET_BYTES,
  authorizationClaims,
  resolveAuthorization,
} from './accessTokenService.js';
import { AuthEventService } from './authEventService.js';
import { resolveCustomClaims } from './customClaimService.js';
import { isUuid } from './oidcAuthContext.js';

/**
 * What the API releases about the user behind a provider sign-in, for one client. The permission
 * claims and `org_id` use the first-party names (ADR 0004) and the session's active organization.
 * `customClaims` is the merged, budgeted set (ADR 0005 E6), kept apart so the edge can release it
 * under its own scope.
 */
export type OidcProviderAccountClaims = OidcAccountClaims &
  AuthorizationClaims & { customClaims: Record<string, unknown> };

type ProviderSession = {
  id: string;
  userId: string;
  organizationId?: string | null;
  recovery?: boolean | null;
  hookClaims?: Record<string, unknown> | null;
};

/** The permission claims a provider token carries together or not at all. */
export const PERMISSION_CLAIMS = [
  'permissions',
  'permissions_omitted',
  'org_roles',
  'org_permissions',
] as const;

/**
 * Computed the way `mintAccessToken` computes a first-party token, plus the client's own set,
 * so `/oidc/accounts/:id` and `/oidc/sign` arrive at the same values.
 */
export async function getOidcAccountClaims(
  session: ProviderSession,
  clientId: string,
  { recordOmission = false }: { recordOmission?: boolean } = {},
): Promise<OidcProviderAccountClaims | null> {
  if (!isUuid(session.userId)) return null;

  const user = await User.findOne({ where: { id: session.userId } });

  if (!user || user.revoked) return null;

  const recovery = session.recovery === true;
  const authorization = await resolveAuthorization({
    userId: user.id,
    roles: user.roles,
    organizationId: session.organizationId,
    recovery,
  });
  // The hook decided its claims for the session's organization, so they go with it.
  const leftOrganization = Boolean(session.organizationId && !authorization.organizationId);

  const budgeted = authorizationClaims(
    authorization,
    recovery
      ? {}
      : await resolveCustomClaims({
          roles: user.roles ?? [],
          organizationRoles: authorization.organizationRoles,
          clientId,
          hookClaims: leftOrganization ? null : session.hookClaims,
        }),
  );

  if (recordOmission && budgeted.customClaimsOmitted) {
    await AuthEventService.logContext({
      userId: user.id,
      sessionId: session.id,
      type: 'custom_claims_omitted',
      metadata: {
        bytes: budgeted.customClaimsOmitted.bytes,
        budgetBytes: AUTHORIZATION_CLAIMS_BUDGET_BYTES,
        clientId,
      },
    });
  }

  return {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified === true,
    ...(user.phone
      ? { phone_number: user.phone, phone_number_verified: user.phoneVerified === true }
      : {}),
    roles: user.roles ?? [],
    org_id: authorization.organizationId,
    ...(recovery ? {} : budgeted.authorization),
    // Every source is held to CustomClaimSetSchema when written, so the merged set is one.
    customClaims: budgeted.customClaims as CustomClaimSet,
  };
}

/** Every claim a provider token for this account may carry, by the name it is signed under. */
export function providerTokenClaims({ customClaims, ...claims }: OidcProviderAccountClaims) {
  return { ...customClaims, ...claims } as Record<string, unknown>;
}
