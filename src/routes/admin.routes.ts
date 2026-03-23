import { createUser, getUserAnomalies, getUserDetail } from '../controllers/admin.js';
import { deleteUser, updateUser } from '../controllers/internal.js';
import { createRouter } from '../lib/createRouter.js';
import { verifyServiceToken } from '../middleware/authenticateServiceToken.js';
import { CreateUserSchema } from '../schemas/admin.createUser.js';
import {
  InternalErrorSchema,
  SuccessMessageSchema,
  UserResponseSchema,
} from '../schemas/admin.responses.js';
import { UpdateUserSchema } from '../schemas/user.patch.schema.js';

const adminRouter = createRouter('/admin');

adminRouter.post(
  '/users',
  {
    // middleware: [verifyServiceToken],
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
    //middleware: [verifyServiceToken],

    schemas: {
      response: {
        200: SuccessMessageSchema,
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
    //middleware: [verifyServiceToken],

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
    //middleware: [verifyServiceToken],
  },
  getUserDetail,
);

adminRouter.get(
  '/users/:userId/anomalies',
  {
    //middleware: [verifyServiceToken]
  },
  getUserAnomalies,
);

export default adminRouter.router;
