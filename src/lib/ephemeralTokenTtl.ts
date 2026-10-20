/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

// The signing expiry and the `ttl` that `/login` and `/registration/register` answer
// both come from this, since callers set their pre-auth cookie from that `ttl`. Kept
// out of token.ts so tests that mock token.ts still read the real value.
export const EPHEMERAL_TOKEN_TTL_SECONDS = 300;
