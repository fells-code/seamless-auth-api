/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import getLogger from '../utils/logger.js';

const logger = getLogger('serviceToken');

export const SERVICE_TOKEN_ENV = 'SEAMLESS_SERVICE_TOKEN';
// Existing deployments (Terraform, Docker images, the managed portal API) still set the
// old name, so it stays a supported fallback rather than a hard rename.
export const LEGACY_SERVICE_TOKEN_ENV = 'API_SERVICE_TOKEN';

type EnvSource = Record<string, string | undefined>;

export type ServiceTokenSource = typeof SERVICE_TOKEN_ENV | typeof LEGACY_SERVICE_TOKEN_ENV;

export interface ResolvedServiceToken {
  value: string | undefined;
  source: ServiceTokenSource | null;
}

export class ServiceTokenConflictError extends Error {
  constructor() {
    super(
      `${SERVICE_TOKEN_ENV} and ${LEGACY_SERVICE_TOKEN_ENV} are both set to different values. ` +
        `Set only ${SERVICE_TOKEN_ENV}, or set both to the same value.`,
    );
    this.name = 'ServiceTokenConflictError';
  }
}

/**
 * The single place that decides which env var supplies the service token. Every consumer
 * reads through here so the two names can never disagree at runtime.
 */
export function resolveServiceToken(env: EnvSource = process.env): ResolvedServiceToken {
  const preferred = env[SERVICE_TOKEN_ENV]?.trim() || undefined;
  const legacy = env[LEGACY_SERVICE_TOKEN_ENV]?.trim() || undefined;

  if (preferred && legacy && preferred !== legacy) {
    throw new ServiceTokenConflictError();
  }

  if (preferred) return { value: preferred, source: SERVICE_TOKEN_ENV };
  if (legacy) return { value: legacy, source: LEGACY_SERVICE_TOKEN_ENV };

  return { value: undefined, source: null };
}

export function getServiceToken(env: EnvSource = process.env): string | undefined {
  return resolveServiceToken(env).value;
}

/**
 * Boot-time check: throws on conflicting values so a misconfigured instance refuses to
 * start, and notes once when only the legacy name is in use.
 */
export function assertServiceTokenConfig(env: EnvSource = process.env) {
  const resolved = resolveServiceToken(env);

  if (resolved.source === LEGACY_SERVICE_TOKEN_ENV) {
    logger.info(
      `Service token read from ${LEGACY_SERVICE_TOKEN_ENV}. ${SERVICE_TOKEN_ENV} is the preferred name; ` +
        `${LEGACY_SERVICE_TOKEN_ENV} remains supported as a fallback.`,
    );
  }

  return resolved;
}
