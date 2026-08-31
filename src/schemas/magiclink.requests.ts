/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export { MagicLinkVerifyParamsSchema } from '@seamless-auth/types';

/**
 * Kept local rather than added to `@seamless-auth/types`, which would need a version bump
 * and a coordinated release across this API and both SDKs before anything could use it.
 * Move it there once a client adopts the field.
 */
export const MagicLinkRequestQuerySchema = z.object({
  /**
   * Where the link should land. Validated against the configured origins, so this cannot
   * be used to point a link on the tenant's domain at somewhere else. Omit it to keep the
   * tenant-wide destination.
   */
  redirectUri: z.url().optional(),
});
