/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  deleteCustomClaims,
  getCustomClaims,
  listCustomClaims,
  setCustomClaims,
} from '../controllers/customClaims.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import {
  CustomClaimListResponseSchema,
  CustomClaimSourceParamSchema,
  CustomClaimSourceResponseSchema,
  SetCustomClaimsRequestSchema,
} from '../schemas/customClaim.schemas.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';

/**
 * Static custom claims (ADR 0005, E6). Instance and organization role sets reach first-party
 * access tokens. OpenID Provider client sets are stored and served here and applied by the
 * provider.
 */
const router = createRouter('/admin');

const tags = ['Admin', 'Custom claims'];
const read = { auth: 'access', tags, middleware: [requireAdmin('read')] };
const write = { auth: 'access', tags, middleware: [requireAdmin('write'), requireStepUp()] };

router.get(
  '/custom-claims',
  {
    ...read,
    summary: 'List custom claim sources',
    description: 'Also lists the reserved names and prefixes, and the per-token budget.',
    schemas: { response: { 200: CustomClaimListResponseSchema } },
  },
  listCustomClaims,
);

router.get(
  '/custom-claims/:sourceKind/:sourceName',
  {
    ...read,
    summary: "Get a source's custom claims",
    schemas: {
      params: CustomClaimSourceParamSchema,
      response: { 200: CustomClaimSourceResponseSchema, 404: ErrorSchema },
    },
  },
  getCustomClaims,
);

router.put(
  '/custom-claims/:sourceKind/:sourceName',
  {
    ...write,
    summary: "Replace a source's custom claims",
    description:
      'Replaces the whole set. Reserved names, values nested deeper than 3 and a set over 1 KiB are refused. The role or client must exist.',
    schemas: {
      params: CustomClaimSourceParamSchema,
      body: SetCustomClaimsRequestSchema,
      response: {
        200: CustomClaimSourceResponseSchema,
        400: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  setCustomClaims,
);

router.delete(
  '/custom-claims/:sourceKind/:sourceName',
  {
    ...write,
    summary: "Delete a source's custom claims",
    schemas: {
      params: CustomClaimSourceParamSchema,
      response: { 200: MessageSchema, 403: StepUpRequiredErrorSchema, 404: ErrorSchema },
    },
  },
  deleteCustomClaims,
);

export default router.router;
