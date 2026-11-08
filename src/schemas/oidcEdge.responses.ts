/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { OidcAccountClaimsSchema } from '@seamless-auth/types';
import { z } from 'zod';

/**
 * The shared schema predates provider tokens carrying authorization claims (seamless-auth-oidc-
 * provider#47). These are the ADR 0004 permission claims under their token names, and the merged
 * custom claims, already held to the shared budget. Custom claim values are any JSON (see
 * `customClaim.schemas.ts` for why not `z.json()`).
 */
export const OidcAccountClaimsResponseSchema = OidcAccountClaimsSchema.extend({
  permissions: z.array(z.string()).optional(),
  permissions_omitted: z.literal(true).optional(),
  org_roles: z.array(z.string()).optional(),
  org_permissions: z.array(z.string()).optional(),
  customClaims: z.record(z.string(), z.unknown()),
});
