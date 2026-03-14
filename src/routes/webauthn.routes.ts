/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import {
  generateWebAuthn,
  registerWebAuthn,
  verifyWebAuthn,
  verifyWebAuthnRegistration,
} from '../controllers/webauthn.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import {
  WebAuthnLoginFinishSchema,
  WebAuthnRegisterFinishSchema,
} from '../schemas/webauthn.requests.js';
import {
  WebAuthnChallengeSchema,
  WebAuthnErrorSchema,
  WebAuthnTokenSuccessSchema,
} from '../schemas/webauthn.responses.js';

const webauthnRouter = createRouter('/webauthn');

webauthnRouter.get(
  '/register/start',
  {
    summary: 'Start WebAuthn registration',
    tags: ['WebAuthn'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      response: {
        200: WebAuthnChallengeSchema,
        403: WebAuthnErrorSchema,
        500: WebAuthnErrorSchema,
      },
    },
  },
  registerWebAuthn,
);

webauthnRouter.post(
  '/register/finish',
  {
    summary: 'Finish WebAuthn registration',
    tags: ['WebAuthn'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      body: WebAuthnRegisterFinishSchema,

      response: {
        200: WebAuthnTokenSuccessSchema,
        403: WebAuthnErrorSchema,
        500: WebAuthnErrorSchema,
      },
    },
  },
  verifyWebAuthnRegistration,
);

webauthnRouter.post(
  '/login/start',
  {
    summary: 'Start WebAuthn login',
    tags: ['WebAuthn'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      response: {
        200: WebAuthnChallengeSchema,
        401: WebAuthnErrorSchema,
        403: WebAuthnErrorSchema,
        500: WebAuthnErrorSchema,
      },
    },
  },
  generateWebAuthn,
);

webauthnRouter.post(
  '/login/finish',
  {
    summary: 'Finish WebAuthn login',
    tags: ['WebAuthn'],
    middleware: [attachAuthMiddleware('ephemeral')],

    schemas: {
      body: WebAuthnLoginFinishSchema,

      response: {
        200: WebAuthnTokenSuccessSchema,
        401: WebAuthnErrorSchema,
        403: WebAuthnErrorSchema,
        500: WebAuthnErrorSchema,
      },
    },
  },
  verifyWebAuthn,
);

export default webauthnRouter.router;
