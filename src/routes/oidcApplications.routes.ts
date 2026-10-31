/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  OidcApplicationCreatedResponseSchema,
  OidcApplicationCreateRequestSchema,
  OidcApplicationIdParamsSchema,
  OidcApplicationKeysRequestSchema,
  OidcApplicationListResponseSchema,
  OidcApplicationResourcesRequestSchema,
  OidcApplicationResourcesResponseSchema,
  OidcApplicationResponseSchema,
  OidcApplicationSecretResponseSchema,
  OidcApplicationUpdateRequestSchema,
} from '@seamless-auth/types';

import {
  createApplication,
  deleteApplication,
  getApplication,
  listApplications,
  putApplicationKeys,
  rotateApplicationSecret,
  updateApplication,
} from '../controllers/oidcApplications.js';
import { getApplicationResources, putApplicationResources } from '../controllers/oidcResources.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import { ErrorSchema, MessageSchema, ValidationErrorSchema } from '../schemas/generic.responses.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';

/**
 * Applications (clients) of the OpenID Provider service (ADR 0001, D12). Available whether
 * or not `oidc_provider_enabled` is on, so they can be set up before the edge is deployed.
 */
const router = createRouter('/admin/applications');

const tags = ['Admin', 'OpenID Provider applications'];
const read = { auth: 'access', tags, middleware: [requireAdmin('read')] };
const write = { auth: 'access', tags, middleware: [requireAdmin('write'), requireStepUp()] };

router.get(
  '',
  {
    ...read,
    summary: 'List OpenID Provider applications',
    schemas: { response: { 200: OidcApplicationListResponseSchema } },
  },
  listApplications,
);

router.post(
  '',
  {
    ...write,
    summary: 'Create an OpenID Provider application',
    description:
      'Public clients authenticate with PKCE (S256) alone. Confidential clients default to `private_key_jwt`. A shared-secret client needs `allow_client_secrets`, and its secret is returned here once. A third-party client needs `third_party_clients_enabled`, and only a first-party client may enable the device grant.',
    schemas: {
      body: OidcApplicationCreateRequestSchema,
      response: {
        201: OidcApplicationCreatedResponseSchema,
        400: ValidationErrorSchema,
        403: StepUpRequiredErrorSchema,
      },
    },
  },
  createApplication,
);

router.get(
  '/:id',
  {
    ...read,
    summary: 'Get an OpenID Provider application',
    schemas: {
      params: OidcApplicationIdParamsSchema,
      response: { 200: OidcApplicationResponseSchema, 404: ErrorSchema },
    },
  },
  getApplication,
);

router.patch(
  '/:id',
  {
    ...write,
    summary: 'Update an OpenID Provider application',
    description:
      'Every create rule is checked again on the merged result. Moving off `private_key_jwt` drops the registered keys, and moving off a shared-secret method drops the secret. A disabled application keeps its settings but cannot sign anyone in or get tokens.',
    schemas: {
      params: OidcApplicationIdParamsSchema,
      body: OidcApplicationUpdateRequestSchema,
      response: {
        200: OidcApplicationResponseSchema,
        400: ValidationErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  updateApplication,
);

router.delete(
  '/:id',
  {
    ...write,
    summary: 'Delete an OpenID Provider application',
    description:
      'Also deletes its resource grants and every provider grant, code and token issued to it.',
    schemas: {
      params: OidcApplicationIdParamsSchema,
      response: { 200: MessageSchema, 403: StepUpRequiredErrorSchema, 404: ErrorSchema },
    },
  },
  deleteApplication,
);

router.post(
  '/:id/secret',
  {
    ...write,
    summary: 'Issue or rotate an application secret',
    description:
      'Only for `client_secret_basic` and `client_secret_post` applications, on an instance with `allow_client_secrets`. The previous secret stops working at once. The secret is returned here only; the API keeps an HMAC of it.',
    schemas: {
      params: OidcApplicationIdParamsSchema,
      response: {
        200: OidcApplicationSecretResponseSchema,
        400: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  rotateApplicationSecret,
);

router.put(
  '/:id/keys',
  {
    ...write,
    summary: 'Register application keys',
    description:
      'Replaces the JWKS or JWKS URI a `private_key_jwt` application signs its client assertions with. Private key members are refused.',
    schemas: {
      params: OidcApplicationIdParamsSchema,
      body: OidcApplicationKeysRequestSchema,
      response: {
        200: OidcApplicationResponseSchema,
        400: ValidationErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  putApplicationKeys,
);

router.get(
  '/:id/resources',
  {
    ...read,
    summary: 'List the resources an application may use',
    schemas: {
      params: OidcApplicationIdParamsSchema,
      response: { 200: OidcApplicationResourcesResponseSchema, 404: ErrorSchema },
    },
  },
  getApplicationResources,
);

router.put(
  '/:id/resources',
  {
    ...write,
    summary: 'Set the resources an application may use',
    description:
      'Replaces the whole set. Each scope must be one the resource declares. The provider signs an access token for a resource only when the application is allowed it and every requested scope.',
    schemas: {
      params: OidcApplicationIdParamsSchema,
      body: OidcApplicationResourcesRequestSchema,
      response: {
        200: OidcApplicationResourcesResponseSchema,
        400: ValidationErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  putApplicationResources,
);

export default router.router;
