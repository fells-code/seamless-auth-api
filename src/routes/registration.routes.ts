/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { register, registerPhone, verifyRegisteredPhone } from '../controllers/registration.js';
import { createRouter } from '../lib/createRouter.js';
import { otpIdentityLimiter, otpIpLimiter } from '../middleware/rateLimit.js';
import { ErrorSchema } from '../schemas/generic.responses.js';
import { VerifyOTPRequestSchema } from '../schemas/otp.requests.js';
import { OTPVerifyTokenSuccessSchema } from '../schemas/otp.responses.js';
import {
  RegisterPhoneRequestSchema,
  RegistrationRequestSchema,
} from '../schemas/registration.requests.js';
import {
  RegisterPhoneSuccessSchema,
  RegistrationSuccessSchema,
} from '../schemas/registration.responses.js';

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

registrationRouter.post(
  '/phone',
  {
    auth: 'access',
    summary: 'Register a phone number for the authenticated user',
    tags: ['Registration'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

    schemas: {
      body: RegisterPhoneRequestSchema,

      response: {
        200: RegisterPhoneSuccessSchema,
        400: ErrorSchema,
        401: ErrorSchema,
        409: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  registerPhone,
);

registrationRouter.post(
  '/phone/verify',
  {
    auth: 'access',
    summary: 'Verify the authenticated user phone number',
    tags: ['Registration'],

    schemas: {
      body: VerifyOTPRequestSchema,

      response: {
        200: OTPVerifyTokenSuccessSchema,
        401: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  verifyRegisteredPhone,
);

export default registrationRouter.router;
