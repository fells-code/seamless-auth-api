import { z } from 'zod';

export const MagicLinkVerifyParamsSchema = z.object({
  token: z.string(),
});
