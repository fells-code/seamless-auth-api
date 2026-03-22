// src/routes/admin.sessions.routes.ts
import { listUserSessions, revokeAllUserSessions } from '../controllers/admin.js';
import { createRouter } from '../lib/createRouter.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { UserIdParamSchema } from '../schemas/admin.sessions.js';
import { InternalErrorSchema } from '../schemas/internal.responses.js';
import {
  SessionDeleteResponseSchema,
  SessionListResponseSchema,
} from '../schemas/session.responses.js';

const adminSessionsRouter = createRouter('/admin/sessions');

adminSessionsRouter.get(
  '/:userId',
  {
    middleware: [verifyServiceToken],
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

adminSessionsRouter.delete(
  '/:userId/revoke-all',
  {
    middleware: [verifyServiceToken],
    tags: ['Admin'],
    schemas: {
      params: UserIdParamSchema,
      response: {
        200: SessionDeleteResponseSchema,
        500: InternalErrorSchema,
      },
    },
  },
  revokeAllUserSessions,
);

export default adminSessionsRouter.router;
