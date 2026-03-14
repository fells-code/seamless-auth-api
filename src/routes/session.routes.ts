/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { listSessions, revokeAllSessions, revokeSession } from '../controllers/sessions.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { SessionIdParamsSchema } from '../schemas/session.params.js';
import {
  SessionDeleteResponseSchema,
  SessionErrorSchema,
  SessionListResponseSchema,
} from '../schemas/session.responses.js';

const sessionsRouter = createRouter('/sessions');

sessionsRouter.get(
  '',
  {
    summary: 'List active sessions',
    tags: ['Sessions'],
    middleware: [attachAuthMiddleware('access')],

    schemas: {
      response: {
        200: SessionListResponseSchema,
        401: SessionErrorSchema,
      },
    },
  },
  listSessions,
);

sessionsRouter.delete(
  '/:id',
  {
    summary: 'Revoke a session',
    tags: ['Sessions'],
    middleware: [attachAuthMiddleware('access')],

    schemas: {
      params: SessionIdParamsSchema,

      response: {
        200: SessionDeleteResponseSchema,
        401: SessionErrorSchema,
        404: SessionErrorSchema,
      },
    },
  },
  revokeSession,
);

sessionsRouter.delete(
  '',
  {
    summary: 'Revoke all sessions',
    tags: ['Sessions'],
    middleware: [attachAuthMiddleware('access')],

    schemas: {
      response: {
        200: SessionDeleteResponseSchema,
        401: SessionErrorSchema,
      },
    },
  },
  revokeAllSessions,
);

export default sessionsRouter.router;
