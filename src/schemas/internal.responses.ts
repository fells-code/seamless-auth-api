import { z } from 'zod';

export const UsersListResponseSchema = z.object({
  users: z.array(z.record(z.unknown())),
});

export const AuthEventsResponseSchema = z.object({
  events: z.array(z.record(z.unknown())),
});

export const CredentialCountSchema = z.object({
  count: z.number(),
});

export const LogsResponseSchema = z.record(z.unknown());

export const InternalErrorSchema = z.object({
  message: z.string(),
});
