/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { SystemConfigSchema } from './systemConfig.schema.js';

export const UpdateSystemConfigResponseSchema = z.object({
  success: z.boolean(),
  updatedKeys: z.array(z.string()),
});

export const UnauthorizedSchema = z.object({
  error: z.string(),
});

export const InvalidPayloadSchema = z.object({
  error: z.string(),
  details: z.unknown().optional(),
});

export const SystemConfigErrorSchema = z.object({
  error: z.string(),
});

export const GetSystemConfigResponseSchema = SystemConfigSchema;
