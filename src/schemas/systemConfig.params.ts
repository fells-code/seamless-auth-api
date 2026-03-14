import { z } from 'zod';

export const SystemConfigParamsSchema = z.object({
  triggeredBy: z.string(),
});

export type SystemConfigParams = z.infer<typeof SystemConfigParamsSchema>;
