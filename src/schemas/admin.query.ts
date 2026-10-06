/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { PaginationQuerySchema } from '@seamless-auth/types';
import { z } from 'zod';

export { UserIdParamSchema } from '@seamless-auth/types';

/**
 * Kept local for the same reason the organization list query is: the response
 * shape is already `{ users, total }`, so only this server's own list route
 * needs the window.
 */
export const AdminUserListQuerySchema = PaginationQuerySchema.extend({
  search: z.string().trim().min(1).max(120).optional(),
});

// Bounds on created_at, half-open: `from` inclusive, `to` exclusive. Both optional, so
// an export with neither is the whole trail.
export const AuthEventExportQuerySchema = z
  .object({
    from: z.iso.datetime({ offset: true }).optional(),
    to: z.iso.datetime({ offset: true }).optional(),
  })
  .refine((query) => !query.from || !query.to || query.from < query.to, {
    message: '`from` must be before `to`',
  });
