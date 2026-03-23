import { z } from 'zod';

const IsoDate = z.coerce.date().transform((d) => d.toISOString());

export const AuthEventSchema = z.object({
  id: z.string(),

  user_id: z.string().nullable().optional(),

  type: z.string(),

  ip_address: z.string().nullable().optional(),

  user_agent: z.string().nullable().optional(),

  metadata: z.record(z.string(), z.unknown()).nullable(),

  created_at: IsoDate,
  updated_at: IsoDate,
});

export type AuthEvent = z.infer<typeof AuthEventSchema>;
