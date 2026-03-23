import { z } from 'zod';

export const UpdateUserSchema = z
  .object({
    email: z.email().optional(),
    phone: z.string().min(5).optional(),
    emailVerified: z.boolean().optional(),
    phoneVerified: z.boolean().optional(),
    roles: z.array(z.string().regex(/^(?!.*[_/\\\s])[A-Za-z0-9-]{1,31}$/)).min(1),
  })
  .strict();
