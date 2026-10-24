/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  cancelAccountRecovery,
  completeAccountRecovery,
  getAccountRecoveryStatus,
  startAccountRecovery,
  verifyAccountRecovery,
} from '../controllers/accountRecovery.js';
import {
  decoyAccountRecoveryStatus,
  decoyCompleteAccountRecovery,
  decoyStartAccountRecovery,
  decoyVerifyAccountRecovery,
} from '../controllers/decoyResponders.js';
import { createRouter } from '../lib/createRouter.js';
import { otpIdentityLimiter, otpIpLimiter } from '../middleware/rateLimit.js';
import {
  AccountRecoveryCancelRequestSchema,
  AccountRecoveryStartRequestSchema,
  AccountRecoveryStartResponseSchema,
  AccountRecoveryStatusSchema,
  AccountRecoveryVerifyRequestSchema,
} from '../schemas/accountRecovery.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { RecoverySessionResponseSchema } from '../schemas/recoveryCodes.js';

const accountRecoveryRouter = createRouter('/recovery');

accountRecoveryRouter.post(
  '/start',
  {
    adapter: { credential: 'preAuth', delivery: true },
    auth: 'ephemeral',
    decoy: decoyStartAccountRecovery,
    middleware: [otpIpLimiter, otpIdentityLimiter],
    summary: 'Start account recovery',
    description:
      'Sends a code to the verified address on file for the channel. Answers the same ' +
      'whether or not the account has one. Not subject to account lockout.',
    tags: ['Recovery'],
    schemas: {
      body: AccountRecoveryStartRequestSchema,
      response: {
        200: AccountRecoveryStartResponseSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  startAccountRecovery,
);

accountRecoveryRouter.post(
  '/verify',
  {
    adapter: { credential: 'preAuth' },
    auth: 'ephemeral',
    decoy: decoyVerifyAccountRecovery,
    middleware: [otpIpLimiter, otpIdentityLimiter],
    summary: 'Verify an account recovery code',
    description:
      'Opens the request started on this attempt, which completes after the configured ' +
      'delay, and tells every verified address how to cancel it. A code for a request ' +
      'that is already open resumes it on this attempt. Five wrong codes void the code.',
    tags: ['Recovery'],
    schemas: {
      body: AccountRecoveryVerifyRequestSchema,
      response: {
        200: AccountRecoveryStatusSchema,
        401: ErrorSchema,
        403: ErrorSchema,
      },
    },
  },
  verifyAccountRecovery,
);

accountRecoveryRouter.get(
  '/status',
  {
    adapter: { credential: 'preAuth' },
    auth: 'ephemeral',
    decoy: decoyAccountRecoveryStatus,
    middleware: [otpIpLimiter, otpIdentityLimiter],
    summary: 'Account recovery status',
    description: 'The request this attempt opened: `pending` until `completesAt`, then `ready`.',
    tags: ['Recovery'],
    schemas: {
      response: {
        200: AccountRecoveryStatusSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  getAccountRecoveryStatus,
);

accountRecoveryRouter.post(
  '/cancel',
  {
    adapter: {},
    middleware: [otpIpLimiter],
    summary: 'Cancel account recovery',
    description:
      'Cancels the open request the token from a recovery notice belongs to. Answers the ' +
      'same whether or not it matched.',
    tags: ['Recovery'],
    schemas: {
      body: AccountRecoveryCancelRequestSchema,
      response: {
        200: MessageSchema,
        400: ErrorSchema,
        403: ErrorSchema,
      },
    },
  },
  cancelAccountRecovery,
);

accountRecoveryRouter.post(
  '/complete',
  {
    adapter: { credential: 'preAuth', issues: 'session' },
    auth: 'ephemeral',
    decoy: decoyCompleteAccountRecovery,
    middleware: [otpIpLimiter, otpIdentityLimiter],
    summary: 'Complete account recovery',
    description:
      'Once the delay has passed, signs out every session on the account and issues a ' +
      'recovery session (`recovery: true`) that can only enroll a new passkey or ' +
      'authenticator app until one is enrolled.',
    tags: ['Recovery'],
    schemas: {
      response: {
        200: RecoverySessionResponseSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        404: ErrorSchema,
        409: ErrorSchema,
      },
    },
  },
  completeAccountRecovery,
);

export default accountRecoveryRouter.router;
