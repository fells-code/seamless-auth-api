import { z } from 'zod';

export const SessionSchema = z.object({
  id: z.string(),
  deviceName: z.string().nullable().optional(),
  ipAddress: z.string().nullable().optional(),
  userAgent: z.string().nullable().optional(),
  lastUsedAt: z.string(),
  expiresAt: z.string(),
  current: z.boolean(),
});

export const SessionListResponseSchema = z.object({
  sessions: z.array(SessionSchema),
});

export const SessionDeleteResponseSchema = z.object({
  message: z.literal('Success'),
});

export const SessionErrorSchema = z.object({
  error: z.string(),
});
