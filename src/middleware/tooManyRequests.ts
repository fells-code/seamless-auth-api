/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * The body every limiter answers a refused request with.
 *
 * An object rather than a string because express-rate-limit sends a string through
 * `res.send`, which lands as `text/html`. Its own default message is a string too, so
 * a limiter that sets nothing is just as inconsistent as one that sets a string. Every
 * other 4xx and 5xx on this API is JSON in this shape, and a client that parses error
 * bodies should not have to special-case one status.
 */
export const TOO_MANY_REQUESTS_BODY = {
  error: 'Too many requests, please try again later',
} as const;
