/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

export const RegistrationSuccessSchema = z.object({
  message: z.string(),
  sub: z.string().optional(),
  token: z.string().optional(),
  ttl: z.string().optional(),
});
