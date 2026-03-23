import { z } from 'zod';

export const CreateUserSchema = z.object({
  email: z.email(),
  phone: z.string(),
  roles: z.array(z.string()).optional(),
});
