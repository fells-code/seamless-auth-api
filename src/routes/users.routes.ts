/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { DeleteCredentialRequestSchema, UpdateCredentialRequestSchema } from '@seamless-auth/types';

import { deleteCredential, deleteUser, getUser, updateCredential } from '../controllers/user.js';
import { createRouter } from '../lib/createRouter.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import { CredentialUpdateResponseSchema } from '../schemas/credential.responses.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { MeResponseSchema } from '../schemas/me.response.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';

const usersRouter = createRouter('/users');

usersRouter.get(
  '/me',
  {
    adapter: { clears: ['preAuth'] },
    auth: 'access',
    allowRecoverySession: true,
    tags: ['Users'],
    summary: 'Get authenticated user',
    schemas: {
      response: MeResponseSchema,
    },
  },
  getUser,
);

usersRouter.post(
  '/credentials',
  {
    auth: 'access',
    tags: ['Users'],
    summary: 'Update credential metadata',

    schemas: {
      body: UpdateCredentialRequestSchema,
      response: {
        200: CredentialUpdateResponseSchema,
      },
    },
  },
  updateCredential,
);

usersRouter.delete(
  '/delete',
  {
    adapter: { clears: ['access', 'registration', 'refresh'] },
    auth: 'access',
    tags: ['Users'],
    summary: 'Delete authenticated user',
    description:
      'Needs a fresh step-up: deleting an account cannot be undone, and an access session ' +
      'alone may be one someone else is holding. An account with no passkey or TOTP cannot ' +
      'step up, so it cannot delete itself; an administrator can.',
    middleware: [requireStepUp()],

    schemas: {
      response: {
        200: MessageSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
        409: ErrorSchema,
        500: ErrorSchema,
      },
    },
  },
  deleteUser,
);

usersRouter.delete(
  '/credentials',
  {
    auth: 'access',
    tags: ['Users'],
    summary: 'Delete credential',

    schemas: {
      body: DeleteCredentialRequestSchema,
      response: {
        200: MessageSchema,
      },
    },
  },
  deleteCredential,
);

export default usersRouter.router;
