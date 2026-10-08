/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  decoySendEmailOtp,
  decoySendLoginEmailOtp,
  decoySendLoginPhoneOtp,
  decoySendPhoneOtp,
  decoyVerifyEmailOtp,
  decoyVerifyLoginEmailOtp,
  decoyVerifyLoginPhoneOtp,
  decoyVerifyPhoneOtp,
} from '../controllers/decoyResponders.js';
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
import { otpIdentityLimiter, otpIpLimiter } from '../middleware/rateLimit.js';
import { ErrorSchema, InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { VerifyOTPRequestSchema } from '../schemas/otp.requests.js';
import { OTPVerifyTokenSuccessSchema } from '../schemas/otp.responses.js';

const otpRouter = createRouter('/otp');

otpRouter.post(
  '/generate-email-otp',
  {
    adapter: { credential: 'registration', delivery: true },
    auth: 'ephemeral',
    summary: 'Generate email OTP',
    decoy: decoySendEmailOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
  '/generate-email-otp',
  {
    adapter: false,
    deprecated: true,
    description:
      'Use POST. A GET that sends a message can be triggered cross-site without a CORS preflight.',
    auth: 'ephemeral',
    summary: 'Generate email OTP',
    decoy: decoySendEmailOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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

otpRouter.post(
  '/generate-phone-otp',
  {
    adapter: { credential: 'registration', delivery: true },
    auth: 'ephemeral',
    summary: 'Generate phone OTP',
    decoy: decoySendPhoneOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
  '/generate-phone-otp',
  {
    adapter: false,
    deprecated: true,
    description:
      'Use POST. A GET that sends a message can be triggered cross-site without a CORS preflight.',
    auth: 'ephemeral',
    summary: 'Generate phone OTP',
    decoy: decoySendPhoneOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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

otpRouter.post(
  '/generate-login-email-otp',
  {
    adapter: { credential: 'preAuth', delivery: true },
    auth: 'ephemeral',
    summary: 'Generate login email OTP',
    decoy: decoySendLoginEmailOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
  '/generate-login-email-otp',
  {
    adapter: false,
    deprecated: true,
    description:
      'Use POST. A GET that sends a message can be triggered cross-site without a CORS preflight.',
    auth: 'ephemeral',
    summary: 'Generate login email OTP',
    decoy: decoySendLoginEmailOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

    schemas: {
      response: {
        200: MessageSchema,
        403: ErrorSchema,
      },
    },
  },
  sendLoginEmailOTP,
);

otpRouter.post(
  '/generate-login-phone-otp',
  {
    adapter: { credential: 'preAuth', delivery: true },
    auth: 'ephemeral',
    summary: 'Generate login phone OTP',
    decoy: decoySendLoginPhoneOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

    schemas: {
      response: {
        200: MessageSchema,
        403: ErrorSchema,
      },
    },
  },
  sendLoginPhoneOTP,
);

otpRouter.get(
  '/generate-login-phone-otp',
  {
    adapter: false,
    deprecated: true,
    description:
      'Use POST. A GET that sends a message can be triggered cross-site without a CORS preflight.',
    auth: 'ephemeral',
    summary: 'Generate login phone OTP',
    decoy: decoySendLoginPhoneOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
    adapter: { credential: 'registration', issues: 'session' },
    auth: 'ephemeral',
    summary: 'Verify email OTP',
    decoy: decoyVerifyEmailOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
    adapter: { credential: 'registration', issues: 'session' },
    auth: 'ephemeral',
    summary: 'Verify phone OTP',
    decoy: decoyVerifyPhoneOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
    adapter: { credential: 'preAuth', issues: 'session' },
    auth: 'ephemeral',
    summary: 'Verify login email OTP',
    decoy: decoyVerifyLoginEmailOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
    adapter: { credential: 'preAuth', issues: 'session' },
    auth: 'ephemeral',
    summary: 'Verify login phone OTP',
    decoy: decoyVerifyLoginPhoneOtp,
    tags: ['OTP'],
    middleware: [otpIpLimiter, otpIdentityLimiter],

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
