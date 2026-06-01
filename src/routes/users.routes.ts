/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { DeleteCredentialRequestSchema, UpdateCredentialRequestSchema } from '@seamless-auth/types';

import { deleteCredential, deleteUser, getUser, updateCredential } from '../controllers/user.js';
import { createRouter } from '../lib/createRouter.js';
import { CredentialUpdateResponseSchema } from '../schemas/credential.responses.js';
import { MessageSchema } from '../schemas/generic.responses.js';
import { MeResponseSchema } from '../schemas/me.response.js';

const usersRouter = createRouter('/users');

usersRouter.get(
  '/me',
  {
    auth: 'access',
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
    auth: 'access',
    tags: ['Users'],
    summary: 'Delete authenticated user',

    schemas: {
      response: MessageSchema,
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
