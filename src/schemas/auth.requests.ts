import { z } from 'zod';

export const LoginRequestSchema = z.object({
  identifier: z.string(),
});

export const RefreshRequestSchema = z.object({});
