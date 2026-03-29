/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { healthCheck, version } from '../controllers/health.js';
import { createRouter } from '../lib/createRouter.js';
import { HealthStatusResponseSchema, VersionResponseSchema } from '../schemas/health.responses.js';

const healthRouter = createRouter('/health');

healthRouter.get(
  '/status',
  {
    summary: 'Health check endpoint',
    tags: ['Health'],

    schemas: {
      response: {
        200: HealthStatusResponseSchema,
      },
    },
  },
  healthCheck,
);

healthRouter.get(
  '/version',
  {
    summary: 'API version information',
    tags: ['Health'],

    schemas: {
      response: {
        200: VersionResponseSchema,
      },
    },
  },
  version,
);

export default healthRouter.router;
