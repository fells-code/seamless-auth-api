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
import { MessageSchema } from '../schemas/generic.responses.js';
import {
  AddOrganizationMemberRequestSchema,
  CreateOrganizationRequestSchema,
  OrganizationIdParamSchema,
  OrganizationMemberParamSchema,
  UpdateOrganizationMemberRequestSchema,
  UpdateOrganizationRequestSchema,
} from '../schemas/organization.requests.js';

const organizationRouter = createRouter('/organizations');

organizationRouter.get(
  '/',
  {
    auth: 'access',
    tags: ['Organizations'],
    summary: 'List organizations for the authenticated user',
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
      },
    },
  },
  removeMember,
);

export default organizationRouter.router;
