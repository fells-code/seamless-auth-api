/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { AuthEventSchema } from '@seamless-auth/types';
import { z } from 'zod';

import { ApiUserSchema } from './user.schema.js';

export const UsersListResponseSchema = z.object({
  users: z.array(ApiUserSchema),
  total: z.number(),
});

export const AuthEventsResponseSchema = z.object({
  events: z.array(AuthEventSchema),
  total: z.number(),
});

export const CredentialCountSchema = z.object({
  count: z.number(),
});
