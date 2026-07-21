/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  createOAuthProvider,
  deleteOAuthProvider,
  listOAuthProviders,
  updateOAuthProvider,
} from '../controllers/oauthProviders.js';
import {
  getAvailableRoles,
  getSystemConfigHandler,
  updateSystemConfig,
} from '../controllers/systemConfig.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { ErrorSchema, InternalErrorSchema } from '../schemas/generic.responses.js';
import {
  OAuthProviderCreateSchema,
  OAuthProviderIdParamSchema,
  OAuthProviderUpdateSchema,
} from '../schemas/oauthProviders.requests.js';
import {
  OAuthProviderDeletedResponseSchema,
  OAuthProviderResponseSchema,
  OAuthProvidersListResponseSchema,
} from '../schemas/oauthProviders.responses.js';
import { SystemConfigPatchSchema } from '../schemas/systemConfig.patch.schema.js';
import {
  AvailableRolesResponseSchema,
  GetSystemConfigResponseSchema,
  InvalidPayloadSchema,
  UpdateSystemConfigResponseSchema,
} from '../schemas/systemConfig.responses.js';

const systemConfigRouter = createRouter('/system-config');

systemConfigRouter.get(
  '/roles',
  {
    auth: 'access',
    summary: 'Get available roles',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],
    schemas: {
      response: {
        200: AvailableRolesResponseSchema,
      },
    },
  },
  getAvailableRoles,
);

systemConfigRouter.get(
  '/admin',
  {
    auth: 'access',
    summary: 'Retrieve system configuration',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],

    schemas: {
      response: {
        200: GetSystemConfigResponseSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  getSystemConfigHandler,
);

systemConfigRouter.patch(
  '/admin',
  {
    auth: 'access',
    summary: 'Update system configuration',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write')],

    schemas: {
      body: SystemConfigPatchSchema,
      response: {
        200: UpdateSystemConfigResponseSchema,
        400: InvalidPayloadSchema,
        401: ErrorSchema,
      },
    },
  },
  updateSystemConfig,
);

systemConfigRouter.get(
  '/oauth-providers',
  {
    auth: 'access',
    summary: 'List configured OAuth providers',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('read')],

    schemas: {
      response: {
        200: OAuthProvidersListResponseSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  listOAuthProviders,
);

systemConfigRouter.post(
  '/oauth-providers',
  {
    auth: 'access',
    summary: 'Add an OAuth provider',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write')],

    schemas: {
      body: OAuthProviderCreateSchema,
      response: {
        201: OAuthProviderResponseSchema,
        400: InvalidPayloadSchema,
        401: ErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  createOAuthProvider,
);

systemConfigRouter.patch(
  '/oauth-providers/:id',
  {
    auth: 'access',
    summary: 'Update an OAuth provider',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write')],

    schemas: {
      params: OAuthProviderIdParamSchema,
      body: OAuthProviderUpdateSchema,
      response: {
        200: OAuthProviderResponseSchema,
        400: InvalidPayloadSchema,
        401: ErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  updateOAuthProvider,
);

systemConfigRouter.delete(
  '/oauth-providers/:id',
  {
    auth: 'access',
    summary: 'Remove an OAuth provider',
    tags: ['SystemConfig'],

    middleware: [requireAdmin('write')],

    schemas: {
      params: OAuthProviderIdParamSchema,
      response: {
        200: OAuthProviderDeletedResponseSchema,
        401: ErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  deleteOAuthProvider,
);

export default systemConfigRouter.router;
