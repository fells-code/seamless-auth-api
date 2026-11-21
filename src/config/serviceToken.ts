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

/**
 * The OpenID Provider service's own secret (ADR 0001, D2). Kept apart from the adapter token
 * so a compromised provider service cannot use adapter-only paths such as external
 * delivery, and an adapter cannot reach the provider's `/oidc/*` routes.
 */
export const OIDC_SERVICE_TOKEN_ENV = 'SEAMLESS_OIDC_SERVICE_TOKEN';

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

export function getOidcServiceToken(env: EnvSource = process.env): string | undefined {
  return env[OIDC_SERVICE_TOKEN_ENV]?.trim() || undefined;
}

export class OidcServiceTokenReuseError extends Error {
  constructor() {
    super(
      `${OIDC_SERVICE_TOKEN_ENV} must differ from ${SERVICE_TOKEN_ENV} and ${LEGACY_SERVICE_TOKEN_ENV}. ` +
        'The provider service and the adapters must not share a credential.',
    );
    this.name = 'OidcServiceTokenReuseError';
  }
}

export const MIN_SERVICE_TOKEN_BYTES = 32;

/**
 * Values that have shipped in compose files, examples, templates and docs. Several are
 * long enough to pass the length check, so a deployment that kept one would otherwise boot.
 */
export const KNOWN_DEFAULT_SERVICE_TOKENS: readonly string[] = [
  'local-development-service-token-not-for-deployment',
  'verify-dev-service-token-not-a-real-secret',
  'local-dev-service-token-at-least-32-chars',
  'GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV',
  'GRAB_FROM_SEAMLESS_AUTH_PORTAL',
  '32-byte-hex-string',
];

const PLACEHOLDER_MARKERS = ['replace-me', 'not-for-deployment', 'not-a-real-secret', 'changeme'];

export function isKnownDefaultServiceToken(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    KNOWN_DEFAULT_SERVICE_TOKENS.some((known) => known.toLowerCase() === lower) ||
    PLACEHOLDER_MARKERS.some((marker) => lower.includes(marker))
  );
}

export class WeakServiceTokenError extends Error {
  constructor(source: ServiceTokenSource, reason: 'short' | 'default') {
    const why =
      reason === 'short'
        ? `is shorter than ${MIN_SERVICE_TOKEN_BYTES} bytes`
        : 'is a published default or placeholder value';
    super(
      `${source} ${why}. It is the key that signs service tokens, so anyone who can guess it ` +
        'can call the API as a trusted adapter. Generate one with: openssl rand -base64 48',
    );
    this.name = 'WeakServiceTokenError';
  }
}

/**
 * Production only: local stacks and the test suite keep short fixed values, and development
 * mode is refused off localhost unless SEAMLESS_ALLOW_INSECURE_DEV is set.
 */
export function assertServiceTokenStrength(
  resolved: ResolvedServiceToken,
  env: EnvSource = process.env,
) {
  if (env.NODE_ENV !== 'production' || !resolved.value || !resolved.source) return;

  if (Buffer.byteLength(resolved.value, 'utf8') < MIN_SERVICE_TOKEN_BYTES) {
    throw new WeakServiceTokenError(resolved.source, 'short');
  }

  if (isKnownDefaultServiceToken(resolved.value)) {
    throw new WeakServiceTokenError(resolved.source, 'default');
  }
}

/**
 * Boot-time check: throws on conflicting values, and in production on a weak or default
 * value, so a misconfigured instance refuses to start. Notes once when only the legacy
 * name is in use.
 */
export function assertServiceTokenConfig(env: EnvSource = process.env) {
  const resolved = resolveServiceToken(env);
  const oidc = getOidcServiceToken(env);
  const legacy = env[LEGACY_SERVICE_TOKEN_ENV]?.trim();

  if (oidc && (oidc === resolved.value || oidc === legacy)) {
    throw new OidcServiceTokenReuseError();
  }

  assertServiceTokenStrength(resolved, env);

  if (resolved.source === LEGACY_SERVICE_TOKEN_ENV) {
    logger.info(
      `Service token read from ${LEGACY_SERVICE_TOKEN_ENV}. ${SERVICE_TOKEN_ENV} is the preferred name; ` +
        `${LEGACY_SERVICE_TOKEN_ENV} remains supported as a fallback.`,
    );
  }

  return resolved;
}
