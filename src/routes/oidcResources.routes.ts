/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  OidcResourceCreateRequestSchema,
  OidcResourceIdParamsSchema,
  OidcResourceListResponseSchema,
  OidcResourceResponseSchema,
  OidcResourceUpdateRequestSchema,
} from '@seamless-auth/types';

import {
  createResource,
  deleteResource,
  getResource,
  listResources,
  updateResource,
} from '../controllers/oidcResources.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import { ErrorSchema, MessageSchema, ValidationErrorSchema } from '../schemas/generic.responses.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';

/**
 * The APIs that OpenID Provider applications request access tokens for (RFC 8707). A
 * token for a resource is a JWT whose `aud` is the resource's identifier and whose
 * `scope` is a subset of what the resource declares and the application is allowed.
 */
const router = createRouter('/admin/resources');

const tags = ['Admin', 'OpenID Provider applications'];
const read = { auth: 'access', tags, middleware: [requireAdmin('read')] };
const write = { auth: 'access', tags, middleware: [requireAdmin('write'), requireStepUp()] };

router.get(
  '',
  {
    ...read,
    summary: 'List OpenID Provider resources',
    schemas: { response: { 200: OidcResourceListResponseSchema } },
  },
  listResources,
);

router.post(
  '',
  {
    ...write,
    summary: 'Create an OpenID Provider resource',
    description:
      'The identifier becomes the `aud` of the resource access tokens and cannot change. It cannot be the API `ISSUER` or `oidc_issuer`.',
    schemas: {
      body: OidcResourceCreateRequestSchema,
      response: {
        201: OidcResourceResponseSchema,
        400: ValidationErrorSchema,
        403: StepUpRequiredErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  createResource,
);

router.get(
  '/:id',
  {
    ...read,
    summary: 'Get an OpenID Provider resource',
    schemas: {
      params: OidcResourceIdParamsSchema,
      response: { 200: OidcResourceResponseSchema, 404: ErrorSchema },
    },
  },
  getResource,
);

router.patch(
  '/:id',
  {
    ...write,
    summary: 'Update an OpenID Provider resource',
    description: 'A scope removed from the resource is also removed from every application.',
    schemas: {
      params: OidcResourceIdParamsSchema,
      body: OidcResourceUpdateRequestSchema,
      response: {
        200: OidcResourceResponseSchema,
        400: ValidationErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  updateResource,
);

router.delete(
  '/:id',
  {
    ...write,
    summary: 'Delete an OpenID Provider resource',
    description: 'Also removes it from every application allowed it.',
    schemas: {
      params: OidcResourceIdParamsSchema,
      response: { 200: MessageSchema, 403: StepUpRequiredErrorSchema, 404: ErrorSchema },
    },
  },
  deleteResource,
);

export default router.router;
