import { z } from 'zod';

export const HealthStatusResponseSchema = z.object({
  message: z.string(),
});

export const VersionResponseSchema = z.object({
  message: z.string().nullable().optional(),
});
