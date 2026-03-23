import { z } from 'zod';

import { AuthEventSchema } from './authEvent.schema.js';
import { UserBaseSchema } from './user.base.js';

export const UsersListResponseSchema = z.object({
  users: z.array(UserBaseSchema),
  total: z.number(),
});

export const AuthEventsResponseSchema = z.object({
  events: z.array(AuthEventSchema),
});

export const CredentialCountSchema = z.object({
  count: z.number(),
});

export const LogsResponseSchema = z.record(z.unknown());

export const InternalErrorSchema = z.object({
  message: z.string(),
});
