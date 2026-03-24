import { z } from 'zod';

export const RegistrationRequestSchema = z.object({
  email: z.email(),
  phone: z.string(),
});
