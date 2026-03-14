/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { login, logout, refreshSession } from '../controllers/authentication.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { LoginRequestSchema } from '../schemas/auth.requests.js';
import {
  AuthErrorSchema,
  LoginSuccessSchema,
  LogoutSuccessSchema,
  RefreshSuccessSchema,
} from '../schemas/auth.responses.js';

const authRouter = createRouter('');

authRouter.post(
  '/login',
  {
    summary: 'Login using identifier (email or phone)',
    tags: ['Authentication'],

    schemas: {
      body: LoginRequestSchema,

      response: {
        200: LoginSuccessSchema,
        400: AuthErrorSchema,
        401: AuthErrorSchema,
        403: AuthErrorSchema,
        500: AuthErrorSchema,
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
        200: LogoutSuccessSchema,
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
        200: RefreshSuccessSchema,
        401: AuthErrorSchema,
        500: AuthErrorSchema,
      },
    },
  },
  refreshSession,
);

export default authRouter.router;
