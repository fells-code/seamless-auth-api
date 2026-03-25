import { z } from 'zod';

export const UserIdParamSchema = z.object({
  userId: z.string(),
});
