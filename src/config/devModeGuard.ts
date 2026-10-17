/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { isIP } from 'node:net';

import getLogger from '../utils/logger.js';

const logger = getLogger('devModeGuard');

const ALLOW_ENV = 'SEAMLESS_ALLOW_INSECURE_DEV';

type EnvSource = Record<string, string | undefined>;

let insecureDevModeActive = false;

/**
 * Whether a host can only be reached from the machine or the private network it runs
 * on. Single-label names count, since that is how containers in one compose project
 * address each other, and no public DNS name has one label.
 */
export function isLocalHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();

  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.test')) {
    return true;
  }

  const version = isIP(host);

  if (version === 4) {
    const [a, b] = host.split('.').map(Number);

    return (
      a === 127 ||
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }

  if (version === 6) {
    return host === '::1' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host);
  }

  return !host.includes('.');
}

function nonLocalUrls(name: string, value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .filter((entry) => {
      try {
        return !isLocalHost(new URL(entry).hostname);
      } catch {
        return false;
      }
    })
    .map((entry) => `${name}=${entry}`);
}

/**
 * Refuses to start in development mode when the deployment is reachable from outside.
 *
 * Anything but `NODE_ENV=production` turns on per-instance signing keys on disk, the
 * `/docs` explorer, the rate limit and conformance escape hatches, and guessable
 * fallback secrets. The bundled compose file sets development mode for a local stack,
 * and copied to a server with its origins changed it would run all of that in public.
 */
export function assertDevModeIsLocal(env: EnvSource = process.env) {
  insecureDevModeActive = false;

  if (env.NODE_ENV === 'production') {
    return;
  }

  const exposed = [
    ...nonLocalUrls('ISSUER', env.ISSUER),
    ...nonLocalUrls('APP_ORIGINS', env.APP_ORIGINS),
  ];

  if (exposed.length === 0) {
    return;
  }

  if (env[ALLOW_ENV] === 'true') {
    insecureDevModeActive = true;
    logger.warn(
      `Running in development mode on a non-local deployment (${exposed.join(', ')}) because ` +
        `${ALLOW_ENV}=true. Development signing keys, fallback secrets and the rate limit and ` +
        `conformance escape hatches are available. Set NODE_ENV=production for a real deployment.`,
    );
    return;
  }

  throw new Error(
    `Refusing to start: NODE_ENV is '${env.NODE_ENV ?? ''}' (development mode) but the ` +
      `deployment is not local: ${exposed.join(', ')}. Development mode uses per-instance ` +
      `signing keys, guessable fallback secrets and allows rate limits to be switched off. ` +
      `Set NODE_ENV=production, or set ${ALLOW_ENV}=true to run development mode here on purpose.`,
  );
}

export function isInsecureDevModeActive() {
  return insecureDevModeActive;
}
