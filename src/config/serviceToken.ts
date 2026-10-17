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
/**
 * Secrets that fall back to the service token when unset, and what rotating the
 * service token would then break. The server adapter holds the service token too, so
 * it is the one most likely to need rotating, and the fallback turns that into a
 * lockout or a forced sign-out.
 */
export const SECRETS_SHARING_SERVICE_TOKEN = [
  {
    env: 'REFRESH_TOKEN_LOOKUP_SECRET',
    onRotate: 'every refresh token stops working and everyone is signed out',
  },
  {
    env: 'TOTP_SECRET_ENCRYPTION_KEY',
    onRotate: 'every stored TOTP secret becomes unreadable and those users must re-enroll',
  },
  { env: 'OAUTH_STATE_SECRET', onRotate: 'OAuth sign-ins in progress fail' },
  { env: 'DECOY_SUBJECT_SECRET', onRotate: 'the decoy subjects for unknown identifiers change' },
] as const;

export function secretsSharingServiceToken(env: EnvSource = process.env) {
  if (!resolveServiceToken(env).value) {
    return [];
  }

  return SECRETS_SHARING_SERVICE_TOKEN.filter(({ env: name }) => !env[name]?.trim());
}

export function assertServiceTokenConfig(env: EnvSource = process.env) {
  const resolved = resolveServiceToken(env);
  const shared = secretsSharingServiceToken(env);

  if (shared.length > 0) {
    logger.warn(
      `These secrets are unset and fall back to the service token: ` +
        shared.map(({ env: name, onRotate }) => `${name} (rotating it: ${onRotate})`).join('; ') +
        `. To separate them safely, set each one to the current service token value first, ` +
        `then rotate the service token. See docs/production-operations.md.`,
    );
  }

  if (resolved.source === LEGACY_SERVICE_TOKEN_ENV) {
    logger.info(
      `Service token read from ${LEGACY_SERVICE_TOKEN_ENV}. ${SERVICE_TOKEN_ENV} is the preferred name; ` +
        `${LEGACY_SERVICE_TOKEN_ENV} remains supported as a fallback.`,
    );
  }

  return resolved;
}
