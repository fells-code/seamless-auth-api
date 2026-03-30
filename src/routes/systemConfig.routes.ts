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
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { ErrorSchema, InternalErrorSchema } from '../schemas/generic.responses.js';
import {
  GetSystemConfigResponseSchema,
  InvalidPayloadSchema,
  UpdateSystemConfigResponseSchema,
} from '../schemas/systemConfig.responses.js';

const systemConfigRouter = createRouter('/system-config');

systemConfigRouter.get(
  '/roles',
  {
    summary: 'Get available roles',
    tags: ['SystemConfig'],

    middleware: [attachAuthMiddleware(), requireAdmin()],
  },
  getAvailableRoles,
);

systemConfigRouter.get(
  '/admin',
  {
    summary: 'Retrieve system configuration',
    tags: ['SystemConfig'],

    middleware: [attachAuthMiddleware(), requireAdmin()],

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
    summary: 'Update system configuration',
    tags: ['SystemConfig'],

    middleware: [attachAuthMiddleware(), requireAdmin()],

    schemas: {
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
