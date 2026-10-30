/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { SystemConfig } from '@seamless-auth/types';

import { getOidcServiceToken, OIDC_SERVICE_TOKEN_ENV } from '../config/serviceToken.js';
import { hasOidcProviderKeys, sharesFirstPartyKey } from '../services/oidcProviderKeys.js';

type ProviderConfig = Pick<SystemConfig, 'oidc_provider_enabled' | 'oidc_issuer' | 'rpid'>;

export const OIDC_PROVIDER_CONFIG_KEYS = ['oidc_provider_enabled', 'oidc_issuer', 'rpid'] as const;

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function withoutTrailingSlash(url: string) {
  return url.replace(/\/+$/, '');
}

/**
 * ADR 0001, D1, D8 and D13. The issuer is the provider service's own origin, so it can
 * never be the API's `ISSUER` (a provider token would then claim to be first-party), and
 * it must sit under `rpid` or passkeys cannot be used on the hosted pages. The flag stays
 * off until both hold and the provider's signing keys are present.
 */
export function oidcProviderConfigProblems(
  config: ProviderConfig,
  env: Record<string, string | undefined> = process.env,
): string[] {
  const problems: string[] = [];
  const { oidc_issuer: issuer, rpid } = config;

  if (issuer) {
    const { protocol, hostname, search, hash } = new URL(issuer);
    const isLoopback = LOOPBACK_HOSTS.has(hostname);

    if (protocol !== 'https:' && !(isLoopback && env.NODE_ENV !== 'production')) {
      problems.push('oidc_issuer must use https');
    }

    if (search || hash) {
      problems.push('oidc_issuer must not have a query or fragment');
    }

    if (env.ISSUER && withoutTrailingSlash(issuer) === withoutTrailingSlash(env.ISSUER)) {
      problems.push('oidc_issuer must differ from the API ISSUER');
    }

    if (hostname !== rpid && !hostname.endsWith(`.${rpid}`)) {
      problems.push(`oidc_issuer host ${hostname} is not covered by rpid ${rpid}`);
    }
  }

  if (config.oidc_provider_enabled) {
    if (!issuer) {
      problems.push('oidc_provider_enabled needs oidc_issuer');
    }

    if (!getOidcServiceToken(env)) {
      problems.push(`oidc_provider_enabled needs ${OIDC_SERVICE_TOKEN_ENV}`);
    }

    if (!hasOidcProviderKeys(env)) {
      problems.push('oidc_provider_enabled needs OIDC_JWKS_ACTIVE_KID and OIDC_JWKS_KEYS');
    } else if (sharesFirstPartyKey(env)) {
      problems.push('OIDC_JWKS_KEYS must not reuse a SEAMLESS_JWKS signing key');
    }
  }

  return problems;
}
