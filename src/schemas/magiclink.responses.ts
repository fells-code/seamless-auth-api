import { z } from 'zod';

export const MagicLinkRequestResponseSchema = z.object({
  message: z.string(),
});

export const MagicLinkVerifyResponseSchema = z.object({
  message: z.literal('Success'),
});

export const MagicLinkPollSuccessSchema = z.object({
  message: z.literal('Success'),
  token: z.string().optional(),
  refreshToken: z.string().optional(),
  sub: z.string().optional(),
  roles: z.array(z.string()).optional(),
  email: z.string().optional(),
  phone: z.string().nullable().optional(),
  ttl: z.number().optional(),
  refreshTtl: z.number().optional(),
});

export const MagicLinkPollPendingSchema = z.object({
  error: z.string(),
});

export const MagicLinkErrorSchema = z.object({
  message: z.string(),
});
