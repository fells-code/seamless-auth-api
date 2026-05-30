/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  addMember,
  createOrganization,
  getOrganization,
  listMembers,
  listOrganizations,
  removeMember,
  switchOrganization,
  updateMember,
  updateOrganization,
} from '../controllers/organizations.js';
import { createRouter } from '../lib/createRouter.js';
import { InternalErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import {
  AddOrganizationMemberRequestSchema,
  CreateOrganizationRequestSchema,
  OrganizationIdParamSchema,
  OrganizationMemberParamSchema,
  UpdateOrganizationMemberRequestSchema,
  UpdateOrganizationRequestSchema,
} from '../schemas/organization.requests.js';
import {
  OrganizationEnvelopeResponseSchema,
  OrganizationListResponseSchema,
  OrganizationMembershipEnvelopeResponseSchema,
  OrganizationMembersResponseSchema,
  OrganizationSwitchResponseSchema,
} from '../schemas/organization.responses.js';

const organizationRouter = createRouter('/organizations');

organizationRouter.get(
  '/',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'List organizations for the authenticated user',
    schemas: {
      response: {
        200: OrganizationListResponseSchema,
      },
    },
  },
  listOrganizations,
);

organizationRouter.post(
  '/',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'Create organization',
    schemas: {
      body: CreateOrganizationRequestSchema,
      response: {
        201: OrganizationEnvelopeResponseSchema,
      },
    },
  },
  createOrganization,
);

organizationRouter.get(
  '/:organizationId',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'Get organization',
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

organizationRouter.patch(
  '/:organizationId',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'Update organization',
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

organizationRouter.post(
  '/:organizationId/switch',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'Switch active organization for the current session',
    schemas: {
      params: OrganizationIdParamSchema,
      response: {
        200: OrganizationSwitchResponseSchema,
        400: InternalErrorSchema,
        404: InternalErrorSchema,
      },
    },
  },
  switchOrganization,
);

organizationRouter.get(
  '/:organizationId/members',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'List organization members',
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

organizationRouter.post(
  '/:organizationId/members',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'Add organization member',
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

organizationRouter.patch(
  '/:organizationId/members/:userId',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'Update organization member',
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

organizationRouter.delete(
  '/:organizationId/members/:userId',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'Remove organization member',
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

export default organizationRouter.router;
