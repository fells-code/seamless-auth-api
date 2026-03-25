import { z } from 'zod';

export const LoginSuccessResponseSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  sub: z.string().optional(),
  identifierType: z.enum(['email', 'phone']).optional(),
  ttl: z.number().optional(),
});

export const RefreshSuccessResponseSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  refreshToken: z.string().optional(),
  sub: z.string().optional(),
  ttl: z.number().optional(),
  refreshTtl: z.number().optional(),
});
