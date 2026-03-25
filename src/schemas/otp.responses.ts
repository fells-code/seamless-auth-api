import { z } from 'zod';

export const OTPVerifyTokenSuccessSchema = z.object({
  message: z.string(),
  token: z.string().optional(),
  refreshTokenHash: z.string().optional(),
});
