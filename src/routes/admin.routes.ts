/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
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
  importUsers,
  listAllSessions,
  listUserSessions,
  recoverUserForDeviceReplacement,
  revokeAllUserSessions,
  revokeUserSessionById,
  updateUser,
} from '../controllers/admin.js';
import { getEnrollment, sendEnrollmentInvites } from '../controllers/enrollment.js';
import {
  addMember,
  createOrganization,
  deleteOrganization,
  getOrganization,
  listAdminOrganizations,
  listMembers,
  removeMember,
  restoreOAuthProvider,
  retireOAuthProvider,
  updateMember,
  updateOrganization,
} from '../controllers/organizations.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import { AdminUserListQuerySchema, UserIdParamSchema } from '../schemas/admin.query.js';
import {
  CreateUserSchema,
  DeviceReplacementRecoverySchema,
  ImportUsersRequestSchema,
  UpdateUserSchema,
} from '../schemas/admin.requests.js';
import {
  AdminUserAnomaliesResponseSchema,
  AdminUserDetailResponseSchema,
  AdminValidationErrorSchema,
  DeviceReplacementRecoveryResponseSchema,
  ImportUsersResponseSchema,
  UserResponseSchema,
} from '../schemas/admin.responses.js';
import {
  AdminEnrollmentQuerySchema,
  AdminEnrollmentResponseSchema,
  EnrollmentInviteRequestSchema,
  EnrollmentInviteResponseSchema,
} from '../schemas/enrollment.js';
import { InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { AuthEventQuerySchema, PaginationQuerySchema } from '../schemas/internal.query.js';
import {
  AuthEventsResponseSchema,
  CredentialCountSchema,
  UsersListResponseSchema,
} from '../schemas/internal.responses.js';
import {
  AddOrganizationMemberRequestSchema,
  AdminOrganizationListQuerySchema,
  CreateOrganizationRequestSchema,
  OrganizationIdParamSchema,
  OrganizationMemberParamSchema,
  OrganizationOAuthProviderParamSchema,
  UpdateOrganizationMemberRequestSchema,
  UpdateOrganizationRequestSchema,
} from '../schemas/organization.requests.js';
import {
  AdminOrganizationListResponseSchema,
  OrganizationEnvelopeResponseSchema,
  OrganizationMembershipEnvelopeResponseSchema,
  OrganizationMembersResponseSchema,
} from '../schemas/organization.responses.js';
import { SessionIdParamsSchema } from '../schemas/session.params.js';
import { SessionListResponseSchema } from '../schemas/session.responses.js';

const adminRouter = createRouter('/admin');

adminRouter.get(
  '/organizations',
  {
    auth: 'access',
    summary: 'List organizations',
    description:
      'Returns a window of organizations ordered by creation date, oldest first. `total` counts every organization matching `search`, not the returned page.',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
    schemas: {
      query: AdminOrganizationListQuerySchema,
      response: {
        200: AdminOrganizationListResponseSchema,
      },
    },
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
      response: {
        201: OrganizationEnvelopeResponseSchema,
      },
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
      response: {
        200: OrganizationEnvelopeResponseSchema,
        404: InternalErrorSchema,
      },
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
      response: {
        200: OrganizationEnvelopeResponseSchema,
        404: InternalErrorSchema,
      },
    },
  },
  updateOrganization,
);

adminRouter.delete(
  '/organizations/:organizationId',
  {
    auth: 'access',
    summary: 'Delete organization',
    description:
      'Deletes the organization and every membership in it. Members are not deleted, and sessions scoped to the organization stay active with no organization, though an access token already issued carries the old organization id until it expires.',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      params: OrganizationIdParamSchema,
      response: {
        200: MessageSchema,
        404: InternalErrorSchema,
      },
    },
  },
  deleteOrganization,
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
      response: {
        200: OrganizationMembersResponseSchema,
        404: InternalErrorSchema,
      },
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
      response: {
        201: OrganizationMembershipEnvelopeResponseSchema,
        404: InternalErrorSchema,
        409: InternalErrorSchema,
      },
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
      response: {
        200: OrganizationMembershipEnvelopeResponseSchema,
        400: InternalErrorSchema,
        404: InternalErrorSchema,
      },
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
        400: InternalErrorSchema,
        404: InternalErrorSchema,
      },
    },
  },
  removeMember,
);

adminRouter.put(
  '/organizations/:organizationId/oauth-providers/:providerId/retirement',
  {
    auth: 'access',
    summary: 'Retire an OAuth provider for an organization',
    description:
      'Members of the organization can no longer sign in through the provider. The callback answers 403 with `code: oauth_provider_retired`, before any account is linked. Retiring also revokes every live session of every member, whichever method started it, so they sign in again with a passkey or another method; the count is recorded on the `admin_oauth_provider_retired` auth event. Repeating the call for a provider already retired revokes nothing. Used to cut an organization over from a legacy identity provider.',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      params: OrganizationOAuthProviderParamSchema,
      response: {
        200: OrganizationEnvelopeResponseSchema,
        404: InternalErrorSchema,
      },
    },
  },
  retireOAuthProvider,
);

adminRouter.delete(
  '/organizations/:organizationId/oauth-providers/:providerId/retirement',
  {
    auth: 'access',
    summary: 'Restore a retired OAuth provider for an organization',
    description:
      'Undoes a retirement, for rolling a cutover back. Idempotent, and accepts the id of a provider that no longer exists so it can be cleared.',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      params: OrganizationOAuthProviderParamSchema,
      response: {
        200: OrganizationEnvelopeResponseSchema,
        404: InternalErrorSchema,
      },
    },
  },
  restoreOAuthProvider,
);

adminRouter.get(
  '/enrollment',
  {
    auth: 'access',
    summary: 'Passkey enrollment progress',
    description:
      'Every active user with their WebAuthn credential count and enrollment status (`none`, `one`, `two_or_more`), optionally scoped to one organization or to imported users. `summary` counts all users matching `organizationId`, `imported` and `search`, whatever `status`; `users` and `total` are the filtered page.',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
    schemas: {
      query: AdminEnrollmentQuerySchema,
      response: {
        200: AdminEnrollmentResponseSchema,
      },
    },
  },
  getEnrollment,
);

adminRouter.post(
  '/enrollment/invites',
  {
    auth: 'access',
    summary: 'Invite users to enroll a passkey',
    description:
      "Emails each target a notice to sign in and add a passkey. The link is the tenant's sign-in page (`signInUrl`, default `<frontend_url>/login`) and carries no credential. Targets are `userIds` (up to 200) or an `organizationId`, whose members at or below `status` are invited 200 at a time, skipping anyone invited in the last day; `remaining` says how many are left. Answers 409 when no sign-in method other than passkey is enabled. With `x-seamless-auth-delivery-mode: external` each result carries the delivery for the caller to send instead.",
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      body: EnrollmentInviteRequestSchema,
      response: {
        200: EnrollmentInviteResponseSchema,
        400: InternalErrorSchema,
        409: InternalErrorSchema,
      },
    },
  },
  sendEnrollmentInvites,
);

adminRouter.get(
  '/users',
  {
    auth: 'access',
    summary: 'List users (internal)',
    description:
      'Returns a window of users. `total` counts every user matching `search`, not the returned page.',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],

    schemas: {
      query: AdminUserListQuerySchema,
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
      response: {
        201: UserResponseSchema,
        400: AdminValidationErrorSchema,
        409: InternalErrorSchema,
      },
    },
  },
  createUser,
);

adminRouter.post(
  '/users/import',
  {
    auth: 'access',
    summary: 'Import users from another identity system',
    description:
      'Creates or updates up to 200 users per request, matched on the source system id and then on email. Imports carry no credentials: an imported user signs in first by registering with the imported email. Roles and memberships are only ever added, never removed, and admin roles are refused. Each row is applied on its own, so one rejected row does not stop the batch. With `dryRun`, nothing is written and the response reports what would happen.',
    tags: ['Admin'],
    middleware: [requireAdmin('write')],
    schemas: {
      body: ImportUsersRequestSchema,
      response: {
        200: ImportUsersResponseSchema,
      },
    },
  },
  importUsers,
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
        400: AdminValidationErrorSchema,
        404: InternalErrorSchema,
      },
    },
  },
  updateUser,
);

adminRouter.post(
  '/users/:userId/recovery/device-replacement',
  {
    auth: 'access',
    summary: 'Prepare a user for admin-assisted device replacement',
    tags: ['Admin'],
    middleware: [requireAdmin('write'), requireStepUp()],

    schemas: {
      params: UserIdParamSchema,
      body: DeviceReplacementRecoverySchema,
      response: {
        200: DeviceReplacementRecoveryResponseSchema,
        400: InternalErrorSchema,
        401: InternalErrorSchema,
        403: InternalErrorSchema,
        404: InternalErrorSchema,
      },
    },
  },
  recoverUserForDeviceReplacement,
);

adminRouter.get(
  '/users/:userId',
  {
    auth: 'access',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
    schemas: {
      params: UserIdParamSchema,
      response: {
        200: AdminUserDetailResponseSchema,
        404: InternalErrorSchema,
      },
    },
  },
  getUserDetail,
);

adminRouter.get(
  '/users/:userId/anomalies',
  {
    auth: 'access',
    tags: ['Admin'],
    middleware: [requireAdmin('read')],
    schemas: {
      params: UserIdParamSchema,
      response: {
        200: AdminUserAnomaliesResponseSchema,
        500: InternalErrorSchema,
      },
    },
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
      response: {
        200: SessionListResponseSchema,
      },
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
  '/sessions/by-id/:id',
  {
    auth: 'access',
    middleware: [requireAdmin('write')],
    tags: ['Admin'],
    schemas: {
      params: SessionIdParamsSchema,
      response: {
        200: MessageSchema,
        404: InternalErrorSchema,
        500: InternalErrorSchema,
      },
    },
  },
  revokeUserSessionById,
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
