/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request } from 'express';

import { User } from '../models/users';

export interface AuthenticatedRequest extends Request {
  user: User;
}
export interface ServiceRequest extends Request {
  clientId?: string | (() => string);
  triggeredBy?: string;
}
