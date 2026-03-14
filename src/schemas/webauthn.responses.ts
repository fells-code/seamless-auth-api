import { z } from 'zod';

export const WebAuthnChallengeSchema = z.record(z.string(), z.unknown());

export const WebAuthnSimpleSuccessSchema = z.object({
  message: z.literal('Success'),
});

export const WebAuthnTokenSuccessSchema = z.object({
  message: z.literal('Success'),
  token: z.string().optional(),
  refreshToken: z.string().optional(),
  refreshTokenHash: z.string().optional(),

  sub: z.string().optional(),
  roles: z.array(z.string()).optional(),
  email: z.string().optional(),
  phone: z.string().nullable().optional(),

  ttl: z.number().optional(),
  refreshTtl: z.number().optional(),
});

export const WebAuthnErrorSchema = z.object({
  message: z.string(),
});
