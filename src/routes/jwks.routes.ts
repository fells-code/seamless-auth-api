/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { jwksHandler } from '../controllers/jwks.js';
import { createRouter } from '../lib/createRouter.js';
import { dynamicJWKSRateLimit } from '../middleware/jwksRateLimit.js';
import { JWKSErrorSchema, JWKSResponseSchema } from '../schemas/jwks.responses.js';

const jwksRouter = createRouter('');

jwksRouter.get(
  '/.well-known/jwks.json',
  {
    summary: 'Public JSON Web Key Set',
    tags: ['JWKS'],

    middleware: [dynamicJWKSRateLimit],

    schemas: {
      response: {
        200: JWKSResponseSchema,
        500: JWKSErrorSchema,
      },
    },
  },
  jwksHandler,
);

export default jwksRouter.router;
