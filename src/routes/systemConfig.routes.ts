/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  getAvailableRoles,
  getSystemConfigHandler,
  updateSystemConfig,
} from '../controllers/systemConfig.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { ErrorSchema, InternalErrorSchema } from '../schemas/generic.responses.js';
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

export default systemConfigRouter.router;
