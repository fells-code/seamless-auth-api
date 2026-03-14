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
