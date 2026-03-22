import { z } from 'zod';

export const UserResponseSchema = z.object({
  user: z.record(z.unknown()),
});

export const SuccessMessageSchema = z.object({
  message: z.literal('Success'),
});

export const InternalErrorSchema = z.object({
  message: z.string(),
});
