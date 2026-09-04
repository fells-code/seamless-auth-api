/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  login,
  logout,
  logoutAllSessions,
  logoutCurrentSession,
  refreshSession,
} from '../controllers/authentication.js';
import { createRouter } from '../lib/createRouter.js';
import { LoginRequestSchema } from '../schemas/auth.requests.js';
import {
  LoginSuccessResponseSchema,
  RefreshSuccessResponseSchema,
} from '../schemas/auth.responses.js';
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
        // No 401. An identifier with no usable account now answers 200 with a decoy
        // pre-auth token rather than a rejection, which is what makes the endpoint
        // non-enumerable. See docs/security-posture.md.
        200: LoginSuccessResponseSchema,
        400: ErrorSchema,
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
    auth: 'access',
    summary: 'Logout all sessions for the current user (deprecated; use DELETE /logout/all)',
    tags: ['Authentication'],
    deprecated: true,

    schemas: {
      response: {
        200: MessageSchema,
      },
    },
  },
  logout,
);

authRouter.delete(
  '/logout',
  {
    auth: 'access',
    summary: 'Logout current session',
    tags: ['Authentication'],

    schemas: {
      response: {
        200: MessageSchema,
        401: ErrorSchema,
      },
    },
  },
  logoutCurrentSession,
);

authRouter.delete(
  '/logout/all',
  {
    auth: 'access',
    summary: 'Logout all sessions for the current user',
    tags: ['Authentication'],

    schemas: {
      response: {
        200: MessageSchema,
      },
    },
  },
  logoutAllSessions,
);

authRouter.post(
  '/refresh',
  {
    summary: 'Refresh access token',
    tags: ['Authentication'],

    schemas: {
      response: {
        200: RefreshSuccessResponseSchema,
        401: ErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  refreshSession,
);

authRouter.router.all('/refresh', (_req, res) => {
  res.setHeader('Allow', 'POST');
  return res.status(405).json({ error: 'Method Not Allowed' });
});

export default authRouter.router;
