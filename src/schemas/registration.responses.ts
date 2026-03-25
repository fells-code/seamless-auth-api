import { z } from 'zod';

export const RegistrationSuccessSchema = z.object({
  message: z.string(),
  sub: z.string().optional(),
  token: z.string().optional(),
  ttl: z.string().optional(),
});
