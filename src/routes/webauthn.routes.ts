/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  generateWebAuthn,
  registerWebAuthn,
  verifyWebAuthn,
  verifyWebAuthnRegistration,
} from '../controllers/webauthn.js';
import { createRouter } from '../lib/createRouter.js';
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

webauthnRouter.get(
  '/register/start',
  {
    auth: 'ephemeral',
    summary: 'Start WebAuthn registration',
    tags: ['WebAuthn'],

    schemas: {
      query: WebAuthnRegisterStartQuerySchema,

      response: {
        200: WebAuthnChallengeSchema,
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
    auth: 'ephemeral',
    summary: 'Finish WebAuthn registration',
    tags: ['WebAuthn'],

    schemas: {
      body: WebAuthnRegisterFinishSchema,

      response: {
        200: WebAuthnTokenSuccessSchema,
        403: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  verifyWebAuthnRegistration,
);

webauthnRouter.post(
  '/login/start',
  {
    auth: 'ephemeral',
    summary: 'Start WebAuthn login',
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
    auth: 'ephemeral',
    summary: 'Finish WebAuthn login',
    tags: ['WebAuthn'],

    schemas: {
      body: WebAuthnLoginFinishSchema,

      response: {
        200: WebAuthnTokenSuccessSchema,
        400: ErrorSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  verifyWebAuthn,
);

export default webauthnRouter.router;
