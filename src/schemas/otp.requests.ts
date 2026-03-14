import { z } from 'zod';

export const VerifyOTPRequestSchema = z.object({
  verificationToken: z.string(),
});
