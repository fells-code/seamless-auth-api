import { z } from 'zod';

import { CredentialBaseSchema } from './credential.base.js';
import { UserBaseSchema } from './user.base.js';

export const MeUserSchema = UserBaseSchema.pick({
  id: true,
  email: true,
  phone: true,
  roles: true,
  lastLogin: true,
});

export const CredentialSchema = CredentialBaseSchema.pick({
  id: true,
  transports: true,
  deviceType: true,
  backedup: true,
  counter: true,
  friendlyName: true,
  lastUsedAt: true,
  platform: true,
  browser: true,
  deviceInfo: true,
  createdAt: true,
});

export const MeResponseSchema = z.object({
  user: MeUserSchema,
  credentials: z.array(CredentialSchema),
});
