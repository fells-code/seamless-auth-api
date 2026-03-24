import { UserSchema } from '@seamless-auth/types';
import { z } from 'zod';

export const UserResponseSchema = z.object({
  user: UserSchema,
});
