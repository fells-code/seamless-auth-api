/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { deleteCredential, deleteUser, getUser, updateCredential } from '../controllers/user.js';
import { createRouter } from '../lib/createRouter.js';
import {
  DeleteCredentialRequestSchema,
  UpdateCredentialRequestSchema,
} from '../schemas/credential.request.js';
import { MeResponseSchema } from '../schemas/me.schema.js';
import { DeleteUserResponseSchema } from '../schemas/user.responses.js';

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
      response: DeleteUserResponseSchema,
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
    },
  },
  deleteCredential,
);

export default usersRouter.router;
