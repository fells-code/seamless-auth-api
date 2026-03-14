/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { getSystemConfigHandler, updateSystemConfig } from '../controllers/systemConfig.js';
import { createRouter } from '../lib/createRouter.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { SystemConfigParamsSchema } from '../schemas/systemConfig.params.js';
import { PatchSystemConfigSchema } from '../schemas/systemConfig.patch.schema.js';
import {
  GetSystemConfigResponseSchema,
  InvalidPayloadSchema,
  SystemConfigErrorSchema,
  UnauthorizedSchema,
  UpdateSystemConfigResponseSchema,
} from '../schemas/systemConfig.responses.js';

const systemConfigRouter = createRouter('/system-config');

systemConfigRouter.get(
  '/:triggeredBy',
  {
    summary: 'Retrieve system configuration',
    tags: ['SystemConfig'],

    middleware: [verifyServiceToken],

    schemas: {
      params: SystemConfigParamsSchema,

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
  '/:triggeredBy',
  {
    summary: 'Update system configuration',
    tags: ['SystemConfig'],

    middleware: [verifyServiceToken],

    schemas: {
      params: SystemConfigParamsSchema,
      body: PatchSystemConfigSchema,

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
