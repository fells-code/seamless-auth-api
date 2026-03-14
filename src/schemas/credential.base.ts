import { z } from 'zod';

import { IsoDate } from './user.base.js';

export const CredentialBaseSchema = z.object({
  id: z.string(),
  transports: z.array(z.string()).nullable().optional(),
  deviceType: z.string().nullable().optional(),
  backedup: z.boolean().nullable().optional(),
  counter: z.number(),
  friendlyName: z.string().nullable().optional(),
  lastUsedAt: IsoDate.nullable().optional(),
  platform: z.string().nullable().optional(),
  browser: z.string().nullable().optional(),
  deviceInfo: z.string().nullable().optional(),
  createdAt: IsoDate,
  updatedAt: IsoDate.optional(),
});

export type CredentialBase = z.infer<typeof CredentialBaseSchema>;
