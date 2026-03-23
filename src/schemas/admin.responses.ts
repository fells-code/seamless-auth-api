import { z } from 'zod';

import { UserBaseSchema } from './user.base.js';

export const UserResponseSchema = z.object({
  user: UserBaseSchema,
});

export const SuccessMessageSchema = z.object({
  message: z.literal('Success'),
});

export const InternalErrorSchema = z.object({
  message: z.string(),
});
