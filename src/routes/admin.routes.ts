/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

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
import {
  addMember,
  createOrganization,
  getOrganization,
  listAdminOrganizations,
  listMembers,
  removeMember,
  updateMember,
  updateOrganization,
} from '../controllers/organizations.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { UserIdParamSchema } from '../schemas/admin.query.js';
import { CreateUserSchema, UpdateUserSchema } from '../schemas/admin.requests.js';
import { UserResponseSchema } from '../schemas/admin.responses.js';
import { InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { AuthEventQuerySchema, PaginationQuerySchema } from '../schemas/internal.query.js';
import {
  AuthEventsResponseSchema,
  CredentialCountSchema,
  UsersListResponseSchema,
} from '../schemas/internal.responses.js';
import {
  AddOrganizationMemberRequestSchema,
  CreateOrganizationRequestSchema,
  OrganizationIdParamSchema,
  OrganizationMemberParamSchema,
  UpdateOrganizationMemberRequestSchema,
  UpdateOrganizationRequestSchema,
} from '../schemas/organization.requests.js';
import { SessionListResponseSchema } from '../schemas/session.responses.js';

const adminRouter = createRouter('/admin');

adminRouter.get(
  '/organizations',
  {
    auth: 'access',
    summary: 'List organizations',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
  },
  listAdminOrganizations,
);

adminRouter.post(
  '/organizations',
  {
    auth: 'access',
    summary: 'Create organization',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      body: CreateOrganizationRequestSchema,
    },
  },
  createOrganization,
);

adminRouter.get(
  '/organizations/:organizationId',
  {
    auth: 'access',
    summary: 'Get organization',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
    schemas: {
      params: OrganizationIdParamSchema,
    },
  },
  getOrganization,
);

adminRouter.patch(
  '/organizations/:organizationId',
  {
    auth: 'access',
    summary: 'Update organization',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      params: OrganizationIdParamSchema,
      body: UpdateOrganizationRequestSchema,
    },
  },
  updateOrganization,
);

adminRouter.get(
  '/organizations/:organizationId/members',
  {
    auth: 'access',
    summary: 'List organization members',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
    schemas: {
      params: OrganizationIdParamSchema,
    },
  },
  listMembers,
);

adminRouter.post(
  '/organizations/:organizationId/members',
  {
    auth: 'access',
    summary: 'Add organization member',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      params: OrganizationIdParamSchema,
      body: AddOrganizationMemberRequestSchema,
    },
  },
  addMember,
);

adminRouter.patch(
  '/organizations/:organizationId/members/:userId',
  {
    auth: 'access',
    summary: 'Update organization member',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      params: OrganizationMemberParamSchema,
      body: UpdateOrganizationMemberRequestSchema,
    },
  },
  updateMember,
);

adminRouter.delete(
  '/organizations/:organizationId/members/:userId',
  {
    auth: 'access',
    summary: 'Remove organization member',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      params: OrganizationMemberParamSchema,
      response: {
        200: MessageSchema,
      },
    },
  },
  removeMember,
);

adminRouter.get(
  '/users',
  {
    auth: 'access',
    summary: 'List users (internal)',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],

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
    auth: 'access',
    middleware: [requireAdmin('read')],
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
    auth: 'access',
    summary: 'Get credential count',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],

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
    auth: 'access',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      body: CreateUserSchema,
    },
  },
  createUser,
);

adminRouter.delete(
  '/users',
  {
    auth: 'access',
    summary: 'Delete user',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],

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
    auth: 'access',
    summary: 'Update user',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],

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
    auth: 'access',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
  },
  getUserDetail,
);

adminRouter.get(
  '/users/:userId/anomalies',
  {
    auth: 'access',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
  },
  getUserAnomalies,
);

adminRouter.get(
  '/sessions',
  {
    auth: 'access',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
    schemas: {
      query: PaginationQuerySchema,
    },
  },
  listAllSessions,
);

adminRouter.get(
  '/sessions/:userId',
  {
    auth: 'access',
    middleware: [requireAdmin('read')],
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
    auth: 'access',
    middleware: [requireAdmin('write')],
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
