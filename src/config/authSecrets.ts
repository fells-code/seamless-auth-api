/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { SystemConfig } from '../schemas/systemConfig.schema.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('authSecrets');

type EnvSource = Record<string, string | undefined>;

/**
 * The server's own secrets. Each one used to fall back to the service token, which the
 * server adapter also holds, so rotating that token after a leak signed everyone out and
 * made stored TOTP secrets unreadable. In production each is now required once the
 * feature that uses it is in use; development keeps a fixed local value so a local stack
 * starts without them (development mode is refused off localhost).
 */
export const AUTH_SECRETS = {
  REFRESH_TOKEN_LOOKUP_SECRET: 'every refresh token, so every session',
  DECOY_SUBJECT_SECRET: 'the decoy subjects /login answers for unknown identifiers',
  TOTP_SECRET_ENCRYPTION_KEY: 'every stored TOTP secret',
  OAUTH_STATE_SECRET: 'OAuth sign-ins in progress',
} as const;

export type AuthSecretName = keyof typeof AUTH_SECRETS;

export class MissingAuthSecretError extends Error {
  readonly variable: AuthSecretName;

  constructor(variable: AuthSecretName) {
    super(`${variable} must be set in production.`);
    this.name = 'MissingAuthSecretError';
    this.variable = variable;
  }
}

function isProduction(env: EnvSource) {
  return env.NODE_ENV === 'production';
}

function devFallback(name: AuthSecretName, env: EnvSource) {
  const app = env.APP_ID ?? 'local';

  switch (name) {
    case 'REFRESH_TOKEN_LOOKUP_SECRET':
      return `dev-refresh-lookup:${app}:${env.ISSUER ?? 'local'}`;
    case 'TOTP_SECRET_ENCRYPTION_KEY':
      return `dev-totp-secret:${app}:${env.ISSUER ?? 'local'}`;
    case 'OAUTH_STATE_SECRET':
      return `dev-oauth-state:${app}`;
    case 'DECOY_SUBJECT_SECRET':
      return `dev-decoy-subject:${app}`;
  }
}

const warnedDevFallback = new Set<AuthSecretName>();

export function authSecret(name: AuthSecretName, env: EnvSource = process.env): string {
  const explicit = env[name]?.trim();
  if (explicit) return explicit;

  if (isProduction(env)) {
    throw new MissingAuthSecretError(name);
  }

  if (!warnedDevFallback.has(name)) {
    warnedDevFallback.add(name);
    logger.warn(`${name} is not set. Using a development-only value; production requires it.`);
  }

  return devFallback(name, env);
}

export function isAuthSecretSet(name: AuthSecretName, env: EnvSource = process.env) {
  return Boolean(env[name]?.trim());
}

/** The secrets a configuration needs, given whether any TOTP credential is stored. */
export function authSecretsRequiredBy(
  config: Pick<SystemConfig, 'oauth_providers'>,
  { totpCredentialsExist }: { totpCredentialsExist: boolean },
): AuthSecretName[] {
  const required: AuthSecretName[] = ['REFRESH_TOKEN_LOOKUP_SECRET', 'DECOY_SUBJECT_SECRET'];

  // TOTP is a factor a user enrolls, not a login method, so the key is needed from the
  // first stored credential; enrollment refuses before that while it is unset.
  if (totpCredentialsExist) {
    required.push('TOTP_SECRET_ENCRYPTION_KEY');
  }

  if ((config.oauth_providers ?? []).length > 0) {
    required.push('OAUTH_STATE_SECRET');
  }

  return required;
}

/**
 * Whether turning on a feature that needs `name` has to be refused: production without
 * the secret. Development is never refused, since it falls back to a local value.
 */
export function productionSecretMissing(name: AuthSecretName, env: EnvSource = process.env) {
  return isProduction(env) && !isAuthSecretSet(name, env);
}

/**
 * Boot check, after system config is bootstrapped. Names every missing secret at once,
 * and says to set each to the current service token value: until now that is what the
 * server used in its place, so the same value keeps existing sessions, TOTP secrets and
 * in-flight OAuth sign-ins valid.
 */
export function assertAuthSecrets(
  config: Pick<SystemConfig, 'oauth_providers'>,
  totpCredentialsExist: boolean,
  env: EnvSource = process.env,
) {
  if (!isProduction(env)) return;

  const missing = authSecretsRequiredBy(config, { totpCredentialsExist }).filter(
    (name) => !isAuthSecretSet(name, env),
  );

  if (missing.length === 0) return;

  throw new Error(
    `Refusing to start: ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} not set. ` +
      `Each protects ${missing.map((name) => AUTH_SECRETS[name]).join('; ')}. ` +
      'They no longer fall back to the service token. To keep existing data valid, set each ' +
      'to the current SEAMLESS_SERVICE_TOKEN value, then give it a value of its own before ' +
      'the service token is next rotated. See docs/production-operations.md.',
  );
}
