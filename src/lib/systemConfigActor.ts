/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthenticatedRequest, ServiceRequest } from '../types/types.js';

// Who a system_config write is attributed to. Service-token callers carry
// req.clientId; admin console callers authenticate with an access token and
// carry req.user instead. Either one sets updatedBy, which marks the row as
// admin-managed so bootstrap stops re-seeding it from env on the next boot.
export function resolveSystemConfigUpdatedBy(req: ServiceRequest): string | null {
  const clientId = typeof req.clientId === 'function' ? req.clientId() : req.clientId;
  if (clientId) return clientId;

  const user = (req as Partial<Pick<AuthenticatedRequest, 'user'>>).user;
  return user?.id ?? null;
}
