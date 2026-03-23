import { z } from 'zod';

export const IsoDate = z.coerce.date().transform((d) => d.toISOString());

export const UserBaseSchema = z.object({
  id: z.string(),
  email: z.email(),
  phone: z.string().nullable().optional(),
  roles: z.array(z.string()),
  lastLogin: IsoDate.optional(),
  createdAt: IsoDate,
  updatedAt: IsoDate.optional(),
  revoked: z.boolean().optional(),
  emailVerified: z.boolean().optional(),
  phoneVerified: z.boolean().optional(),
  verified: z.boolean().optional(),
});

export type UserBase = z.infer<typeof UserBaseSchema>;
