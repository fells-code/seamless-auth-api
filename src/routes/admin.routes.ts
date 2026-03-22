import { deleteUser, updateUser } from '../controllers/internal.js';
import { createRouter } from '../lib/createRouter.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import {
  InternalErrorSchema,
  SuccessMessageSchema,
  UserResponseSchema,
} from '../schemas/admin.responses.js';
import { UpdateUserSchema } from '../schemas/user.patch.schema.js';

const adminRouter = createRouter('/admin');

adminRouter.patch(
  '/users/:triggeredBy/:userId',
  {
    summary: 'Update user',
    tags: ['Admin'],
    middleware: [verifyServiceToken],

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

adminRouter.delete(
  '/users',
  {
    summary: 'Delete user',
    tags: ['Admin'],
    middleware: [verifyServiceToken],

    schemas: {
      response: {
        200: SuccessMessageSchema,
        500: InternalErrorSchema,
      },
    },
  },
  deleteUser,
);

export default adminRouter.router;
