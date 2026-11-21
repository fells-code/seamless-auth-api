/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
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
   * Where the link should land. Must match an entry of `magic_link_redirect_uris` exactly,
   * or, when that is empty, the `/verify-magiclink` page on a configured origin. Omit it to
   * keep the tenant-wide destination.
   */
  redirectUri: z.url().optional(),
});

/**
 * The `code` is the value the link carries in its fragment (`#code=`). The query string
 * holds only the token, so a URL that leaks through a Referer or a log is not enough to
 * confirm the link.
 */
export const MagicLinkConfirmBodySchema = z.object({
  code: z.string().min(1).max(256),
});
