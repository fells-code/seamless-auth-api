/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';

import { Session } from '../models/sessions.js';
import { User } from '../models/users.js';

/**
 * A request whose route params are single-valued.
 *
 * Express 5 widens `req.params` to `string | string[]` because path-to-regexp v8 can
 * repeat a param (`:name*`, `*splat`). Every API route here uses plain `:name` segments,
 * which never repeat, so the array half is unreachable for them. Handlers on a wildcard
 * route must keep the wider `Request` type.
 */
export type RouteRequest = Request<Record<string, string>>;

export interface AuthenticatedRequest extends RouteRequest {
  user: User;
  sessionId: Session['id'];
  /**
   * Set when the ephemeral token's subject resolved to no account, meaning `user` is the
   * decoy stand-in rather than a row. `defineRoute` reads this to send the request to the
   * route's decoy responder, so a real handler never observes it as true.
   */
  decoy?: boolean;
  organizationId?: string | null;
  clientId?: string;
  trustedClientIp?: string;
}
export interface ServiceRequest extends RouteRequest {
  clientId?: string | (() => string);
  triggeredBy?: string;
  trustedClientIp?: string;
}
