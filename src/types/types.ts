/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Request } from 'express';

import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';

export interface AuthenticatedRequest extends Request {
  user: User;
  sessionId: Session['id'];
}
export interface ServiceRequest extends Request {
  clientId?: string | (() => string);
  triggeredBy?: string;
}
