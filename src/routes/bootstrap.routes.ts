/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { createAdminBootstrapInviteHandler } from '../controllers/bootstrap.js';
import { createRouter } from '../lib/createRouter.js';
import {
  BootstrapAdminInviteBodySchema,
  BootstrapAdminInviteResponseSchema,
  BootstrapErrorResponseSchema,
} from '../schemas/bootstrap.schema.js';

const bootstrapRouter = createRouter('');

bootstrapRouter.post(
  '/internal/bootstrap/admin-invite',
  {
    summary: 'Create a one-time bootstrap admin invite',
    description:
      'Internal bootstrap endpoint used to create the first admin invite before any admin exists.',
    tags: ['Internal Bootstrap'],
    schemas: {
      body: BootstrapAdminInviteBodySchema,
      response: {
        201: BootstrapAdminInviteResponseSchema,
        401: BootstrapErrorResponseSchema,
        403: BootstrapErrorResponseSchema,
        409: BootstrapErrorResponseSchema,
        410: BootstrapErrorResponseSchema,
        500: BootstrapErrorResponseSchema,
      },
    },
  },
  createAdminBootstrapInviteHandler,
);

export default bootstrapRouter.router;
