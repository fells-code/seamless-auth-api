/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { decoyVerifyTotpLogin } from '../controllers/decoyResponders.js';
import {
  disableCurrentTotp,
  getCurrentTotpStatus,
  startCurrentTotpEnrollment,
  verifyCurrentTotpEnrollment,
  verifyTotpLogin,
  verifyTotpMfa,
} from '../controllers/totp.js';
import { createRouter } from '../lib/createRouter.js';
import { otpIdentityLimiter, otpIpLimiter } from '../middleware/rateLimit.js';
import { requireDeviceSessionStepUp } from '../middleware/requireDeviceSessionStepUp.js';
import { requireFactorEnrollmentProof } from '../middleware/requireFactorEnrollmentProof.js';
import {
  ErrorSchema,
  InternalErrorSchema,
  MessageSchema,
  SecretRequiredSchema,
} from '../schemas/generic.responses.js';
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
    allowRecoverySession: true,
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
    middleware: [requireFactorEnrollmentProof],
    auth: 'access',
    allowRecoverySession: true,
    summary: 'Start TOTP enrollment',
    tags: ['TOTP'],

    schemas: {
      response: {
        200: TotpEnrollmentStartSchema,
        401: ErrorSchema,
        409: SecretRequiredSchema,
        500: InternalErrorSchema,
      },
    },
  },
  startCurrentTotpEnrollment,
);

totpRouter.post(
  '/enroll/verify',
  {
    middleware: [requireFactorEnrollmentProof, otpIpLimiter, otpIdentityLimiter],
    auth: 'access',
    allowRecoverySession: true,
    summary: 'Verify TOTP enrollment',
    description:
      'From a recovery session, enrolling lifts its restriction once the login hooks allow it. A ' +
      "hook can refuse: 403 `login_denied` with the hook's `message`, or 503 " +
      '`login_hook_unavailable`. Either way the recovery session is revoked and the new factor is ' +
      'kept, so the user signs in with it.',
    tags: ['TOTP'],

    schemas: {
      body: TotpVerifyRequestSchema,

      response: {
        200: TotpVerifySuccessSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        503: ErrorSchema,
      },
    },
  },
  verifyCurrentTotpEnrollment,
);

totpRouter.post(
  '/disable',
  {
    middleware: [requireDeviceSessionStepUp, otpIpLimiter, otpIdentityLimiter],
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
    adapter: { credential: 'preAuth', issues: 'session' },
    middleware: [otpIpLimiter, otpIdentityLimiter],
    auth: 'ephemeral',
    summary: 'Verify TOTP during login',
    decoy: decoyVerifyTotpLogin,
    tags: ['TOTP'],

    schemas: {
      body: TotpVerifyRequestSchema,

      response: {
        200: WebAuthnTokenSuccessSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        503: ErrorSchema,
      },
    },
  },
  verifyTotpLogin,
);

totpRouter.post(
  '/verify-mfa',
  {
    middleware: [otpIpLimiter, otpIdentityLimiter],
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
