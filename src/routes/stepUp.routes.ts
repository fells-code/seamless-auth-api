/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  finishWebAuthnStepUp,
  getStepUpStatus,
  startWebAuthnStepUp,
} from '../controllers/stepUp.js';
import { createRouter } from '../lib/createRouter.js';
import { ErrorSchema, InternalErrorSchema } from '../schemas/generic.responses.js';
import { StepUpStatusSchema, StepUpSuccessSchema } from '../schemas/stepUp.responses.js';
import { WebAuthnLoginFinishSchema } from '../schemas/webauthn.requests.js';
import { WebAuthnChallengeSchema } from '../schemas/webauthn.responses.js';

const stepUpRouter = createRouter('/step-up');

stepUpRouter.get(
  '/status',
  {
    auth: 'access',
    summary: 'Get current session step-up status',
    tags: ['Step-Up'],

    schemas: {
      response: {
        200: StepUpStatusSchema,
        401: ErrorSchema,
      },
    },
  },
  getStepUpStatus,
);

stepUpRouter.post(
  '/webauthn/start',
  {
    auth: 'access',
    summary: 'Start WebAuthn step-up authentication',
    tags: ['Step-Up'],

    schemas: {
      response: {
        200: WebAuthnChallengeSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  startWebAuthnStepUp,
);

stepUpRouter.post(
  '/webauthn/finish',
  {
    auth: 'access',
    summary: 'Finish WebAuthn step-up authentication',
    tags: ['Step-Up'],

    schemas: {
      body: WebAuthnLoginFinishSchema,

      response: {
        200: StepUpSuccessSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  finishWebAuthnStepUp,
);

export default stepUpRouter.router;
