import { z } from 'zod';

export const OTPSuccessSchema = z.object({
  message: z.literal('success'),
});

export const OTPVerifySuccessSchema = z.object({
  message: z.literal('Success'),
});

export const OTPVerifyTokenSuccessSchema = z.object({
  message: z.literal('Success'),
  token: z.string().optional(),
  refreshTokenHash: z.string().optional(),
});

export const OTPInvalidSchema = z.object({
  message: z.string(),
});

export const OTPServerErrorSchema = z.object({
  message: z.literal('Internal server error'),
});
