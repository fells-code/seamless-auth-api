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
import { VerifyOTPRequestSchema } from '../schemas/otp.requests.js';
import {
  OTPInvalidSchema,
  OTPServerErrorSchema,
  OTPSuccessSchema,
  OTPVerifyTokenSuccessSchema,
} from '../schemas/otp.responses.js';

const otpRouter = createRouter('/otp');

otpRouter.get(
  '/generate-email-otp',
  {
    summary: 'Generate email OTP',
    tags: ['OTP'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      response: {
        200: OTPSuccessSchema,
        400: OTPInvalidSchema,
        500: OTPServerErrorSchema,
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
        200: OTPSuccessSchema,
        400: OTPInvalidSchema,
        500: OTPServerErrorSchema,
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
        200: OTPSuccessSchema,
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
        200: OTPSuccessSchema,
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
        401: OTPInvalidSchema,
        500: OTPServerErrorSchema,
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
        401: OTPInvalidSchema,
        500: OTPServerErrorSchema,
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
        401: OTPInvalidSchema,
        500: OTPServerErrorSchema,
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
        401: OTPInvalidSchema,
        500: OTPServerErrorSchema,
      },
    },
  },
  verifyLoginPhoneNumber,
);

export default otpRouter.router;
