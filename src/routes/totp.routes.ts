/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  disableCurrentTotp,
  getCurrentTotpStatus,
  startCurrentTotpEnrollment,
  verifyCurrentTotpEnrollment,
  verifyTotpLogin,
  verifyTotpMfa,
} from '../controllers/totp.js';
import { createRouter } from '../lib/createRouter.js';
import { ErrorSchema, InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { StepUpSuccessSchema } from '../schemas/stepUp.responses.js';
import { TotpVerifyRequestSchema } from '../schemas/totp.requests.js';
import {
  TotpEnrollmentStartSchema,
  TotpStatusSchema,
  TotpVerifySuccessSchema,
} from '../schemas/totp.responses.js';
import { WebAuthnTokenSuccessSchema } from '../schemas/webauthn.responses.js';

const totpRouter = createRouter('/totp');

totpRouter.get(
  '/status',
  {
    auth: 'access',
    summary: 'Get TOTP status for the current user',
    tags: ['TOTP'],

    schemas: {
      response: {
        200: TotpStatusSchema,
        401: ErrorSchema,
      },
    },
  },
  getCurrentTotpStatus,
);

totpRouter.post(
  '/enroll/start',
  {
    auth: 'access',
    summary: 'Start TOTP enrollment',
    tags: ['TOTP'],

    schemas: {
      response: {
        200: TotpEnrollmentStartSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  startCurrentTotpEnrollment,
);

totpRouter.post(
  '/enroll/verify',
  {
    auth: 'access',
    summary: 'Verify TOTP enrollment',
    tags: ['TOTP'],

    schemas: {
      body: TotpVerifyRequestSchema,

      response: {
        200: TotpVerifySuccessSchema,
        401: ErrorSchema,
      },
    },
  },
  verifyCurrentTotpEnrollment,
);

totpRouter.post(
  '/disable',
  {
    auth: 'access',
    summary: 'Disable TOTP for the current user',
    tags: ['TOTP'],

    schemas: {
      body: TotpVerifyRequestSchema,

      response: {
        200: MessageSchema,
        401: ErrorSchema,
      },
    },
  },
  disableCurrentTotp,
);

totpRouter.post(
  '/verify-login',
  {
    auth: 'ephemeral',
    summary: 'Verify TOTP during login',
    tags: ['TOTP'],

    schemas: {
      body: TotpVerifyRequestSchema,

      response: {
        200: WebAuthnTokenSuccessSchema,
        401: ErrorSchema,
      },
    },
  },
  verifyTotpLogin,
);

totpRouter.post(
  '/verify-mfa',
  {
    auth: 'access',
    summary: 'Verify TOTP for MFA or step-up authentication',
    tags: ['TOTP'],

    schemas: {
      body: TotpVerifyRequestSchema,

      response: {
        200: StepUpSuccessSchema,
        401: ErrorSchema,
      },
    },
  },
  verifyTotpMfa,
);

export default totpRouter.router;
