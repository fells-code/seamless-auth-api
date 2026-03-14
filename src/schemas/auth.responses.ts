import { z } from 'zod';

export const LoginSuccessSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  sub: z.string().optional(),
  identifierType: z.enum(['email', 'phone']).optional(),
  ttl: z.number().optional(),
});

export const LogoutSuccessSchema = z.object({
  message: z.string(),
});

export const RefreshSuccessSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  refreshToken: z.string().optional(),
  sub: z.string().optional(),
  ttl: z.number().optional(),
  refreshTtl: z.number().optional(),
});

export const AuthErrorSchema = z.object({
  message: z.string(),
});
