/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { CreateUserSchema, UpdateUserSchema } from '@seamless-auth/types';

import {
  createUser,
  deleteUser,
  getAuthEvents,
  getCredentialsCount,
  getUserAnomalies,
  getUserDetail,
  getUsers,
  listAllSessions,
  listUserSessions,
  revokeAllUserSessions,
  updateUser,
} from '../controllers/admin.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { UserIdParamSchema } from '../schemas/admin.query.js';
import { UserResponseSchema } from '../schemas/admin.responses.js';
import { InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { AuthEventQuerySchema, PaginationQuerySchema } from '../schemas/internal.query.js';
import {
  AuthEventsResponseSchema,
  CredentialCountSchema,
  UsersListResponseSchema,
} from '../schemas/internal.responses.js';
import { SessionListResponseSchema } from '../schemas/session.responses.js';

const adminRouter = createRouter('/admin');

adminRouter.get(
  '/users',
  {
    summary: 'List users (internal)',
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],

    schemas: {
      response: {
        200: UsersListResponseSchema,
        500: InternalErrorSchema,
      },
    },
  },
  getUsers,
);

adminRouter.get(
  '/auth-events',
  {
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    tags: ['Admin'],
    schemas: {
      query: AuthEventQuerySchema,
      response: {
        200: AuthEventsResponseSchema,
      },
    },
  },
  getAuthEvents,
);

adminRouter.get(
  '/credential-count',
  {
    summary: 'Get credential count',
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],

    schemas: {
      response: {
        200: CredentialCountSchema,
        500: InternalErrorSchema,
      },
    },
  },
  getCredentialsCount,
);

adminRouter.post(
  '/users',
  {
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    schemas: {
      body: CreateUserSchema,
    },
  },
  createUser,
);

adminRouter.delete(
  '/users',
  {
    summary: 'Delete user',
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],

    schemas: {
      response: {
        200: MessageSchema,
        500: InternalErrorSchema,
      },
    },
  },
  deleteUser,
);

adminRouter.patch(
  '/users/:userId',
  {
    summary: 'Update user',
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],

    schemas: {
      body: UpdateUserSchema,

      response: {
        200: UserResponseSchema,
        400: InternalErrorSchema,
        404: InternalErrorSchema,
      },
    },
  },
  updateUser,
);

adminRouter.get(
  '/users/:userId',
  {
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
  },
  getUserDetail,
);

adminRouter.get(
  '/users/:userId/anomalies',
  {
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
  },
  getUserAnomalies,
);

adminRouter.get(
  '/sessions',
  {
    tags: ['Admin'],
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    schema: {
      query: PaginationQuerySchema,
    },
  },
  listAllSessions,
);

adminRouter.get(
  '/sessions/:userId',
  {
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    tags: ['Admin'],
    schemas: {
      params: UserIdParamSchema,
      response: {
        200: SessionListResponseSchema,
        500: InternalErrorSchema,
      },
    },
  },
  listUserSessions,
);

adminRouter.delete(
  '/sessions/:userId/revoke-all',
  {
    middleware: [verifyServiceToken, attachAuthMiddleware(), requireAdmin()],
    tags: ['Admin'],
    schemas: {
      params: UserIdParamSchema,
      response: {
        200: MessageSchema,
        500: InternalErrorSchema,
      },
    },
  },
  revokeAllUserSessions,
);

export default adminRouter.router;
