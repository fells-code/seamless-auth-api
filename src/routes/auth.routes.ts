/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { login, logout, refreshSession } from '../controllers/authentication.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { LoginRequestSchema } from '../schemas/auth.requests.js';
import { LoginSuccessResponseSchema } from '../schemas/auth.responses.js';
import { ErrorSchema, InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';

const authRouter = createRouter('');

authRouter.post(
  '/login',
  {
    summary: 'Login using identifier (email or phone)',
    tags: ['Authentication'],

    schemas: {
      body: LoginRequestSchema,

      response: {
        200: LoginSuccessResponseSchema,
        400: ErrorSchema,
        401: ErrorSchema,
        403: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  login,
);

authRouter.get(
  '/logout',
  {
    summary: 'Logout current user',
    tags: ['Authentication'],
    middleware: [attachAuthMiddleware('access')],

    schemas: {
      response: {
        200: MessageSchema,
      },
    },
  },
  logout,
);

authRouter.post(
  '/refresh',
  {
    summary: 'Refresh access token',
    tags: ['Authentication'],
    middleware: [attachAuthMiddleware('access')],

    schemas: {
      response: {
        200: MessageSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  refreshSession,
);

export default authRouter.router;
