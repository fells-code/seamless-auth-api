import { SessionSchema } from '@seamless-auth/types';
import { z } from 'zod';

export const SessionListResponseSchema = z.object({
  sessions: z.array(SessionSchema),
  total: z.number(),
});
