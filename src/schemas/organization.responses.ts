/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

// Local names predate the shared package: it calls these OrganizationSchema and
// OrganizationMembershipSchema. Unlike the old local copies, their timestamps are
// parsed as ISO dates rather than z.any(), so createdAt/updatedAt serialize as strings.
export {
  OrganizationMembershipSchema as OrganizationMembershipResponseSchema,
  OrganizationSchema as OrganizationResponseSchema,
} from '@seamless-auth/types';
export {
  AdminOrganizationListResponseSchema,
  OrganizationEnvelopeResponseSchema,
  OrganizationListResponseSchema,
  OrganizationMembershipEnvelopeResponseSchema,
  OrganizationMembersResponseSchema,
  OrganizationSwitchResponseSchema,
} from '@seamless-auth/types';
