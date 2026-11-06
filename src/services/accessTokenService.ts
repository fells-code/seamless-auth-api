/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { Transaction } from 'sequelize';

import { type AuthorizationClaims, signAccessToken } from '../lib/token.js';
import { permissionsForRoles } from './permissionService.js';

/**
 * How much of an access token the permission arrays may take, serialized. A server adapter
 * keeps the whole token inside a signed cookie, so it is base64 encoded twice under the
 * browser's 4 KiB limit. `tests/unit/services/accessTokenService.spec.ts` builds that cookie
 * at this budget and holds it under the limit.
 */
export const PERMISSION_CLAIMS_BUDGET_BYTES = 1024;

type AuthorizationInput = {
  roles: string[] | null | undefined;
  recovery: boolean;
  transaction?: Transaction;
};

export type ResolvedAuthorization = {
  roles: string[];
  permissions: string[];
};

/** A recovery session can only enroll a new factor, so it holds no permissions. */
export async function resolveAuthorization({
  roles,
  recovery,
  transaction,
}: AuthorizationInput): Promise<ResolvedAuthorization> {
  return {
    roles: roles ?? [],
    permissions: recovery ? [] : await permissionsForRoles('instance', roles, transaction),
  };
}

/**
 * All or nothing. A partial list looks complete and denies silently, so a set that does not
 * fit is replaced with a marker that sends a guard to `GET /users/me/permissions`.
 */
export function authorizationClaims({ permissions }: ResolvedAuthorization): AuthorizationClaims {
  const claims = { permissions };

  if (Buffer.byteLength(JSON.stringify(claims)) > PERMISSION_CLAIMS_BUDGET_BYTES) {
    return { permissions_omitted: true };
  }

  return claims;
}

/**
 * Every first-party access token is minted here, so sign-in, refresh, organization switch and
 * session exchange cannot disagree about what a token grants.
 */
export async function mintAccessToken({
  session,
  user,
  transaction,
}: {
  session: { id: string; organizationId?: string | null; recovery?: boolean | null };
  user: { id: string; roles?: string[] | null };
  transaction?: Transaction;
}) {
  const recovery = session.recovery === true;
  const authorization = await resolveAuthorization({ roles: user.roles, recovery, transaction });

  return signAccessToken(session.id, user.id, user.roles ?? [], session.organizationId, {
    recovery,
    authorization: authorizationClaims(authorization),
  });
}
