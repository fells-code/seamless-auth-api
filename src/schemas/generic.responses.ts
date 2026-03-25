import z from 'zod';

export const MessageSchema = z.object({
  message: z.string(),
});

export const ErrorSchema = z.object({
  message: z.string().optional(),
  error: z.string(),
});

export const InternalErrorSchema = z.object({
  message: z.string().optional(),
  error: z.string(),
});
