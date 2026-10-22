/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { decoyRedeemRecoveryCode } from '../controllers/decoyResponders.js';
import {
  createRecoveryCodes,
  getRecoveryCodes,
  redeemRecoveryCodeLogin,
} from '../controllers/recoveryCodes.js';
import { createRouter } from '../lib/createRouter.js';
import { otpIdentityLimiter, otpIpLimiter } from '../middleware/rateLimit.js';
import { ErrorSchema } from '../schemas/generic.responses.js';
import {
  RecoveryCodeRedeemRequestSchema,
  RecoveryCodesGeneratedSchema,
  RecoveryCodesStatusSchema,
  RecoverySessionResponseSchema,
} from '../schemas/recoveryCodes.js';

const recoveryCodesRouter = createRouter('/recovery-codes');

recoveryCodesRouter.get(
  '/',
  {
    auth: 'access',
    allowRecoverySession: true,
    summary: 'Recovery code status',
    description: 'How many of the current set are unused, and when the set was made.',
    tags: ['Recovery'],
    schemas: {
      response: {
        200: RecoveryCodesStatusSchema,
        401: ErrorSchema,
      },
    },
  },
  getRecoveryCodes,
);

recoveryCodesRouter.post(
  '/',
  {
    auth: 'access',
    allowRecoverySession: true,
    summary: 'Generate recovery codes',
    description:
      'Returns a new set of single-use codes, the only time they are shown, and invalidates ' +
      'the previous set. Replacing an existing set needs a fresh step-up.',
    tags: ['Recovery'],
    schemas: {
      response: {
        201: RecoveryCodesGeneratedSchema,
        401: ErrorSchema,
        403: ErrorSchema,
      },
    },
  },
  createRecoveryCodes,
);

recoveryCodesRouter.post(
  '/redeem',
  {
    adapter: { credential: 'preAuth', issues: 'session' },
    auth: 'ephemeral',
    decoy: decoyRedeemRecoveryCode,
    middleware: [otpIpLimiter, otpIdentityLimiter],
    summary: 'Sign in with a recovery code',
    description:
      'Spends one code and issues a recovery session (`recovery: true`), which can only ' +
      'enroll a new passkey or authenticator app, manage recovery codes, read the user and ' +
      'sign out until a factor is enrolled. Not subject to account lockout.',
    tags: ['Recovery'],
    schemas: {
      body: RecoveryCodeRedeemRequestSchema,
      response: {
        200: RecoverySessionResponseSchema,
        401: ErrorSchema,
        403: ErrorSchema,
      },
    },
  },
  redeemRecoveryCodeLogin,
);

export default recoveryCodesRouter.router;
