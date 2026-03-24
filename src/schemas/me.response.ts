import { CredentialApiSchema, UserSchema } from '@seamless-auth/types';
import { z } from 'zod';

export const MeResponseSchema = z.object({
  user: UserSchema.pick({
    id: true,
    email: true,
    phone: true,
    roles: true,
    lastLogin: true,
  }),
  credentials: z.array(CredentialApiSchema),
});
