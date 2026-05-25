/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { ROLE_NAME_PATTERN } from '../lib/scopedRoles.js';

export const RoleNameSchema = z.string().trim().regex(ROLE_NAME_PATTERN);
