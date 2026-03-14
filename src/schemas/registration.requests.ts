import { z } from 'zod';

export const RegistrationRequestSchema = z.object({
  email: z.string().email(),
  phone: z.string(),
});
