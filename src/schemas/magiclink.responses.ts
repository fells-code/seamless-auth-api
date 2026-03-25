import { z } from 'zod';

export const MagicLinkPollSuccessSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  refreshToken: z.string().optional(),
  sub: z.string().optional(),
  roles: z.array(z.string()).optional(),
  email: z.string().optional(),
  phone: z.string().nullable().optional(),
  ttl: z.number().optional(),
  refreshTtl: z.number().optional(),
});
