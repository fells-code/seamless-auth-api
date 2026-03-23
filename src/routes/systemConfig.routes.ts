/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import {
  getAvailableRoles,
  getSystemConfigHandler,
  updateSystemConfig,
} from '../controllers/systemConfig.js';
import { createRouter } from '../lib/createRouter.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { SystemConfigParamsSchema } from '../schemas/systemConfig.params.js';
import {
  GetSystemConfigResponseSchema,
  InvalidPayloadSchema,
  SystemConfigErrorSchema,
  UnauthorizedSchema,
  UpdateSystemConfigResponseSchema,
} from '../schemas/systemConfig.responses.js';
import { SystemConfigSchema } from '../schemas/systemConfig.schema.js';

const systemConfigRouter = createRouter('/system-config');

systemConfigRouter.get(
  '/roles',
  {
    summary: 'Get available roles',
    tags: ['SystemConfig'],
  },
  getAvailableRoles,
);

systemConfigRouter.get(
  '/admin',
  {
    summary: 'Retrieve system configuration',
    tags: ['SystemConfig'],

    //middleware: [verifyServiceToken],

    schemas: {
      response: {
        200: GetSystemConfigResponseSchema,
        401: UnauthorizedSchema,
        500: SystemConfigErrorSchema,
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

    //middleware: [verifyServiceToken],

    schemas: {
      response: {
        200: UpdateSystemConfigResponseSchema,
        400: InvalidPayloadSchema,
        401: UnauthorizedSchema,
      },
    },
  },
  updateSystemConfig,
);

export default systemConfigRouter.router;
