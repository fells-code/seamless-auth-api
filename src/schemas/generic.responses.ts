/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import z from 'zod';

export const MessageSchema = z.object({
  message: z.string(),
});

export const ErrorSchema = z.object({
  message: z.string().optional(),
  error: z.string(),
});

export const InternalErrorSchema = z.object({
  message: z.string().optional(),
  error: z.string(),
});
