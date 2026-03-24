/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import {
  sendEmailOTP,
  sendPhoneOTP,
  verifyEmail,
  verifyLoginEmail,
  verifyLoginPhoneNumber,
  verifyPhoneNumber,
} from '../controllers/otp.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { ErrorSchema, InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { VerifyOTPRequestSchema } from '../schemas/otp.requests.js';
import { OTPVerifyTokenSuccessSchema } from '../schemas/otp.responses.js';

const otpRouter = createRouter('/otp');

otpRouter.get(
  '/generate-email-otp',
  {
    summary: 'Generate email OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

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
    summary: 'Generate phone OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

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
    summary: 'Generate login email OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      response: {
        200: MessageSchema,
      },
    },
  },
  sendEmailOTP,
);

otpRouter.get(
  '/generate-login-phone-otp',
  {
    summary: 'Generate login phone OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      response: {
        200: MessageSchema,
      },
    },
  },
  sendPhoneOTP,
);

otpRouter.post(
  '/verify-email-otp',
  {
    summary: 'Verify email OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      body: VerifyOTPRequestSchema,

      response: {
        200: OTPVerifyTokenSuccessSchema,
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
    summary: 'Verify phone OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      body: VerifyOTPRequestSchema,

      response: {
        200: OTPVerifyTokenSuccessSchema,
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
    summary: 'Verify login email OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

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
    summary: 'Verify login phone OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

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
