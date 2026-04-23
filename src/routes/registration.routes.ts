/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { register } from '../controllers/registration.js';
import { createRouter } from '../lib/createRouter.js';
import { ErrorSchema } from '../schemas/generic.responses.js';
import { RegistrationRequestSchema } from '../schemas/registration.requests.js';
import { RegistrationSuccessSchema } from '../schemas/registration.responses.js';

const registrationRouter = createRouter('/registration');

registrationRouter.post(
  '/register',
  {
    summary: 'Register a new user',
    tags: ['Registration'],

    schemas: {
      body: RegistrationRequestSchema,

      response: {
        200: RegistrationSuccessSchema,
        400: ErrorSchema,
        409: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  register,
);

export default registrationRouter.router;
