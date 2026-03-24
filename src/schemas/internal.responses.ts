import { AuthEventSchema, UserSchema } from '@seamless-auth/types';
import { z } from 'zod';

export const UsersListResponseSchema = z.object({
  users: z.array(UserSchema),
  total: z.number(),
});

export const AuthEventsResponseSchema = z.object({
  events: z.array(AuthEventSchema),
  total: z.number(),
});

export const CredentialCountSchema = z.object({
  count: z.number(),
});
