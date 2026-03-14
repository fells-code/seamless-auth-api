/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { z } from 'zod';

export const UpdateCredentialRequestSchema = z.object({
  id: z.string(),

  friendlyName: z.string().min(1).max(128).optional(),

  deviceInfo: z.string().max(256).optional(),
});

export type UpdateCredentialRequest = z.infer<typeof UpdateCredentialRequestSchema>;

export const DeleteCredentialRequestSchema = z.object({
  id: z.string(),
});

export type DeleteCredentialRequest = z.infer<typeof DeleteCredentialRequestSchema>;
