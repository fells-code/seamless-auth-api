import { z } from 'zod';

export const SessionIdParamsSchema = z.object({
  id: z.string(),
});
