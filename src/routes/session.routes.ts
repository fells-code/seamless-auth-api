/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { listSessions, revokeAllSessions, revokeSession } from '../controllers/sessions.js';
import { createRouter } from '../lib/createRouter.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { SessionIdParamsSchema } from '../schemas/session.params.js';
import { SessionListResponseSchema } from '../schemas/session.responses.js';

const sessionsRouter = createRouter('/sessions');

sessionsRouter.get(
  '',
  {
    auth: 'access',
    summary: 'List active sessions',
    tags: ['Sessions'],

    schemas: {
      response: {
        200: SessionListResponseSchema,
        401: ErrorSchema,
      },
    },
  },
  listSessions,
);

sessionsRouter.delete(
  '/:id',
  {
    auth: 'access',
    summary: 'Revoke a session',
    tags: ['Sessions'],

    schemas: {
      params: SessionIdParamsSchema,

      response: {
        200: MessageSchema,
        401: ErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  revokeSession,
);

sessionsRouter.delete(
  '',
  {
    auth: 'access',
    summary: 'Revoke all sessions',
    tags: ['Sessions'],

    schemas: {
      response: {
        200: MessageSchema,
        401: ErrorSchema,
      },
    },
  },
  revokeAllSessions,
);

export default sessionsRouter.router;
