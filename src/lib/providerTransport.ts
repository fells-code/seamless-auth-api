/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { guardedRequest } from './oauthProviderPolicy.js';

/**
 * The network leg of `providerFetch`, in a module of its own so the test suite can stand
 * in for the socket without replacing the destination checks around it.
 */
export function sendProviderRequest(
  url: URL,
  init: RequestInit,
  env: Record<string, string | undefined>,
): Promise<Response> {
  return guardedRequest(url, init, env);
}
