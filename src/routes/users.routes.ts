/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { DeleteCredentialRequestSchema, UpdateCredentialRequestSchema } from '@seamless-auth/types';

import { deleteCredential, deleteUser, getUser, updateCredential } from '../controllers/user.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
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

    middleware: [attachAuthMiddleware],

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

    middleware: [attachAuthMiddleware],

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

    middleware: [attachAuthMiddleware],

    schemas: {
      body: DeleteCredentialRequestSchema,
    },
  },
  deleteCredential,
);

export default usersRouter.router;
