import { z } from 'zod';

export const MetricsQuerySchema = z.object({
  userId: z.string().optional(),
  from: z.string().optional(),
  to: z.string().optional(),
  interval: z.enum(['hour', 'day']).optional().default('hour'),
});
