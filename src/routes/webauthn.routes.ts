/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  decoyFinishWebAuthnLogin,
  decoyStartWebAuthnLogin,
} from '../controllers/decoyResponders.js';
import {
  generateWebAuthn,
  registerWebAuthn,
  verifyWebAuthn,
  verifyWebAuthnRegistration,
} from '../controllers/webauthn.js';
import { createRouter } from '../lib/createRouter.js';
import { requireFactorEnrollmentProof } from '../middleware/requireFactorEnrollmentProof.js';
import { CredentialUpdateResponseSchema } from '../schemas/credential.responses.js';
import { ErrorSchema, InternalErrorSchema } from '../schemas/generic.responses.js';
import {
  WebAuthnAssertionStartSchema,
  WebAuthnLoginFinishSchema,
  WebAuthnRegisterFinishSchema,
  WebAuthnRegisterStartQuerySchema,
} from '../schemas/webauthn.requests.js';
import {
  WebAuthnChallengeSchema,
  WebAuthnTokenSuccessSchema,
} from '../schemas/webauthn.responses.js';

const webauthnRouter = createRouter('/webauthn');

// Enrollment takes an access session, not a pre-auth one. `/login` and
// `/registration/register` both mint an ephemeral token for an account that already
// exists from an email address alone, so accepting one here let anyone who knew an
// address enroll a credential and take the account over. Every shipped signup flow
// verifies an email OTP before it offers a passkey, and that step issues a session, so
// nothing legitimate reaches enrollment without one.
webauthnRouter.get(
  '/register/start',
  {
    middleware: [requireFactorEnrollmentProof],
    auth: 'access',
    allowRecoverySession: true,
    summary: 'Start WebAuthn registration',
    tags: ['WebAuthn'],

    schemas: {
      query: WebAuthnRegisterStartQuerySchema,

      response: {
        200: WebAuthnChallengeSchema,
        400: ErrorSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  registerWebAuthn,
);

webauthnRouter.post(
  '/register/finish',
  {
    middleware: [requireFactorEnrollmentProof],
    auth: 'access',
    allowRecoverySession: true,
    summary: 'Finish WebAuthn registration',
    description:
      'From a recovery session, enrolling lifts its restriction once the login hooks allow it. A ' +
      "hook can refuse: 403 `login_denied` with the hook's `message`, or 503 " +
      '`login_hook_unavailable`. Either way the recovery session is revoked and the new factor is ' +
      'kept, so the user signs in with it.',
    tags: ['WebAuthn'],

    schemas: {
      body: WebAuthnRegisterFinishSchema,

      response: {
        200: CredentialUpdateResponseSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        500: ErrorSchema,
        503: ErrorSchema,
      },
    },
  },
  verifyWebAuthnRegistration,
);

webauthnRouter.post(
  '/login/start',
  {
    adapter: { credential: 'preAuth' },
    auth: 'ephemeral',
    summary: 'Start WebAuthn login',
    decoy: decoyStartWebAuthnLogin,
    tags: ['WebAuthn'],

    schemas: {
      body: WebAuthnAssertionStartSchema,

      response: {
        200: WebAuthnChallengeSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  generateWebAuthn,
);

webauthnRouter.post(
  '/login/finish',
  {
    adapter: { credential: 'preAuth', issues: 'session' },
    auth: 'ephemeral',
    summary: 'Finish WebAuthn login',
    decoy: decoyFinishWebAuthnLogin,
    tags: ['WebAuthn'],

    schemas: {
      body: WebAuthnLoginFinishSchema,

      response: {
        200: WebAuthnTokenSuccessSchema,
        400: ErrorSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        500: InternalErrorSchema,
        503: ErrorSchema,
      },
    },
  },
  verifyWebAuthn,
);

export default webauthnRouter.router;
