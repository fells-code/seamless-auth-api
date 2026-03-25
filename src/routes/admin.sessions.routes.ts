import { listUserSessions, revokeAllUserSessions } from '../controllers/admin.js';
import { createRouter } from '../lib/createRouter.js';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { UserIdParamSchema } from '../schemas/admin.query.js';
import { InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { SessionListResponseSchema } from '../schemas/session.responses.js';

const adminSessionsRouter = createRouter('/admin/sessions');

adminSessionsRouter.get(
  '/:userId',
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

adminSessionsRouter.delete(
  '/:userId/revoke-all',
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

export default adminSessionsRouter.router;
