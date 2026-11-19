/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { RequestHandler } from 'express';

/**
 * How long a pre-auth answer takes at minimum, in milliseconds.
 *
 * A real account and a decoy do different work: the real path reads and writes rows and
 * waits on the mail or SMS provider, while a decoy answers from the subject alone. Left
 * alone, that difference is an oracle in its own right: identical bodies that arrive at
 * measurably different times still answer the question. Holding every answer until a
 * floor removes the difference as long as both paths finish under it, so a deployment
 * whose provider is slower than the floor should raise it.
 *
 * An environment variable rather than a `system_config` key on purpose. The config schema
 * is shared through `@seamless-auth/types`, so a key there means a coordinated release
 * across both SDKs for what is an operational tuning knob, not a policy a deployment
 * changes at runtime.
 *
 * Set it to `0` to turn the floor off, which the test suite does so that it is exercised
 * deliberately in one place rather than paid for in every test.
 */
export function responseFloorMs() {
  const configured = Number(process.env.LOGIN_RESPONSE_FLOOR_MS);

  return Number.isFinite(configured) && configured >= 0 ? configured : 250;
}

export async function holdUntilFloor(startedAt: number) {
  const remaining = responseFloorMs() - (Date.now() - startedAt);

  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}

/**
 * Holds whatever the rest of the route answers, success or failure, until the floor.
 * Mounted ahead of authentication so the subject lookup is inside the measured time.
 */
export const holdResponseToFloor: RequestHandler = (_req, res, next) => {
  const startedAt = Date.now();
  const end = res.end.bind(res) as (...args: unknown[]) => typeof res;

  res.end = ((...args: unknown[]) => {
    const remaining = responseFloorMs() - (Date.now() - startedAt);

    if (remaining <= 0) {
      return end(...args);
    }

    setTimeout(() => end(...args), remaining);
    return res;
  }) as typeof res.end;

  next();
};
