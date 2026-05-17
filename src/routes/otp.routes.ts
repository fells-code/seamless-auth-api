/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  sendEmailOTP,
  sendLoginEmailOTP,
  sendLoginPhoneOTP,
  sendPhoneOTP,
  verifyEmail,
  verifyLoginEmail,
  verifyLoginPhoneNumber,
  verifyPhoneNumber,
} from '../controllers/otp.js';
import { createRouter } from '../lib/createRouter.js';
import { ErrorSchema, InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { VerifyOTPRequestSchema } from '../schemas/otp.requests.js';
import { OTPVerifyTokenSuccessSchema } from '../schemas/otp.responses.js';

const otpRouter = createRouter('/otp');

otpRouter.get(
  '/generate-email-otp',
  {
    auth: 'ephemeral',
    summary: 'Generate email OTP',
    tags: ['OTP'],

    schemas: {
      response: {
        200: MessageSchema,
        400: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  sendEmailOTP,
);

otpRouter.get(
  '/generate-phone-otp',
  {
    auth: 'ephemeral',
    summary: 'Generate phone OTP',
    tags: ['OTP'],

    schemas: {
      response: {
        200: MessageSchema,
        400: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  sendPhoneOTP,
);

otpRouter.get(
  '/generate-login-email-otp',
  {
    auth: 'ephemeral',
    summary: 'Generate login email OTP',
    tags: ['OTP'],

    schemas: {
      response: {
        200: MessageSchema,
        403: ErrorSchema,
      },
    },
  },
  sendLoginEmailOTP,
);

otpRouter.get(
  '/generate-login-phone-otp',
  {
    auth: 'ephemeral',
    summary: 'Generate login phone OTP',
    tags: ['OTP'],

    schemas: {
      response: {
        200: MessageSchema,
        403: ErrorSchema,
      },
    },
  },
  sendLoginPhoneOTP,
);

otpRouter.post(
  '/verify-email-otp',
  {
    auth: 'ephemeral',
    summary: 'Verify email OTP',
    tags: ['OTP'],

    schemas: {
      body: VerifyOTPRequestSchema,

      response: {
        200: OTPVerifyTokenSuccessSchema,
        403: ErrorSchema,
        401: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  verifyEmail,
);

otpRouter.post(
  '/verify-phone-otp',
  {
    auth: 'ephemeral',
    summary: 'Verify phone OTP',
    tags: ['OTP'],

    schemas: {
      body: VerifyOTPRequestSchema,

      response: {
        200: OTPVerifyTokenSuccessSchema,
        403: ErrorSchema,
        401: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  verifyPhoneNumber,
);

otpRouter.post(
  '/verify-login-email-otp',
  {
    auth: 'ephemeral',
    summary: 'Verify login email OTP',
    tags: ['OTP'],

    schemas: {
      body: VerifyOTPRequestSchema,

      response: {
        200: OTPVerifyTokenSuccessSchema,
        401: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  verifyLoginEmail,
);

otpRouter.post(
  '/verify-login-phone-otp',
  {
    auth: 'ephemeral',
    summary: 'Verify login phone OTP',
    tags: ['OTP'],

    schemas: {
      body: VerifyOTPRequestSchema,

      response: {
        200: OTPVerifyTokenSuccessSchema,
        401: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  verifyLoginPhoneNumber,
);

export default otpRouter.router;
