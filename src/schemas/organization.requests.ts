/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { PaginationQuerySchema } from '@seamless-auth/types';
import { z } from 'zod';

export {
  AddOrganizationMemberRequestSchema,
  CreateOrganizationRequestSchema,
  OrganizationIdParamSchema,
  OrganizationMemberParamSchema,
  UpdateOrganizationMemberRequestSchema,
  UpdateOrganizationRequestSchema,
} from '@seamless-auth/types';

/**
 * Kept local rather than added to the shared package: the response shape is already
 * `{ organizations, total }`, so only this server's own list route needs the window.
 */
export const AdminOrganizationListQuerySchema = PaginationQuerySchema.extend({
  search: z.string().trim().min(1).max(120).optional(),
});
