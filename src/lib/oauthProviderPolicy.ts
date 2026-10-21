/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

import type { OAuthProviderConfig } from '../schemas/systemConfig.schema.js';

type EnvSource = Record<string, string | undefined>;

/**
 * Provider configuration is written by administrators, but the client secret and the
 * endpoints it is sent to are the server's own trust. A provider may only name an env
 * var shaped like an OAuth client secret, so configuration cannot point the token
 * exchange at a secret the server holds for something else (signing keys, the service
 * token, database credentials).
 */
export const CLIENT_SECRET_ENV_PATTERN = /^[A-Z][A-Z0-9_]{0,59}_CLIENT_SECRET$/;

export const PRIVATE_PROVIDER_HOSTS_ENV = 'OAUTH_PROVIDER_PRIVATE_HOSTS';

const PROVIDER_URL_FIELDS = ['authorizationUrl', 'tokenUrl', 'userInfoUrl', 'jwksUri'] as const;

const nonPublic = new BlockList();
nonPublic.addSubnet('0.0.0.0', 8, 'ipv4');
nonPublic.addSubnet('10.0.0.0', 8, 'ipv4');
nonPublic.addSubnet('100.64.0.0', 10, 'ipv4');
nonPublic.addSubnet('127.0.0.0', 8, 'ipv4');
nonPublic.addSubnet('169.254.0.0', 16, 'ipv4');
nonPublic.addSubnet('172.16.0.0', 12, 'ipv4');
nonPublic.addSubnet('192.0.0.0', 24, 'ipv4');
nonPublic.addSubnet('192.168.0.0', 16, 'ipv4');
nonPublic.addSubnet('198.18.0.0', 15, 'ipv4');
nonPublic.addSubnet('224.0.0.0', 3, 'ipv4');
nonPublic.addAddress('::', 'ipv6');
nonPublic.addAddress('::1', 'ipv6');
nonPublic.addSubnet('fc00::', 7, 'ipv6');
nonPublic.addSubnet('fe80::', 10, 'ipv6');
nonPublic.addSubnet('ff00::', 8, 'ipv6');

// Never reachable, even for an allowlisted host: link-local carries cloud instance
// metadata, and the unspecified address means this machine.
const neverReachable = new BlockList();
neverReachable.addSubnet('0.0.0.0', 8, 'ipv4');
neverReachable.addSubnet('169.254.0.0', 16, 'ipv4');
neverReachable.addAddress('::', 'ipv6');
neverReachable.addSubnet('fe80::', 10, 'ipv6');

function unmapIPv4(address: string) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  return mapped ? mapped[1] : address;
}

function inList(list: BlockList, address: string) {
  const plain = unmapIPv4(address.replace(/^\[|\]$/g, ''));
  const version = isIP(plain);
  if (!version) return false;
  return list.check(plain, version === 4 ? 'ipv4' : 'ipv6');
}

export function isNonPublicAddress(address: string) {
  return inList(nonPublic, address);
}

function isProduction(env: EnvSource) {
  return env.NODE_ENV === 'production';
}

function privateHostsAllowed(env: EnvSource) {
  return new Set(
    (env[PRIVATE_PROVIDER_HOSTS_ENV] ?? '')
      .split(',')
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function clientSecretEnvProblem(name: string): string | null {
  return CLIENT_SECRET_ENV_PATTERN.test(name)
    ? null
    : `clientSecretEnv "${name}" must be an env var name ending in _CLIENT_SECRET, for example GOOGLE_CLIENT_SECRET`;
}

function urlProblem(field: string, value: string, env: EnvSource): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return `${field} is not a valid URL`;
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return `${field} must use https`;
  }

  if (!isProduction(env)) {
    return null;
  }

  if (url.protocol !== 'https:') {
    return `${field} must use https`;
  }

  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (isIP(unmapIPv4(host)) && inList(nonPublic, host)) {
    if (inList(neverReachable, host) || !privateHostsAllowed(env).has(host)) {
      return `${field} points at a non-public address; list the host in ${PRIVATE_PROVIDER_HOSTS_ENV} to allow it`;
    }
  }

  return null;
}

/** Problems with a provider that configuration must not be able to store. */
export function oauthProviderProblems(
  provider: OAuthProviderConfig,
  env: EnvSource = process.env,
): string[] {
  const problems: string[] = [];

  const secretProblem = clientSecretEnvProblem(provider.clientSecretEnv);
  if (secretProblem) problems.push(secretProblem);

  for (const field of PROVIDER_URL_FIELDS) {
    const value = provider[field];
    if (typeof value !== 'string' || !value) continue;
    const problem = urlProblem(field, value, env);
    if (problem) problems.push(problem);
  }

  return problems;
}

export class OAuthProviderPolicyError extends Error {}

/**
 * Checks where a provider request is about to go. In production the host must resolve
 * only to public addresses, unless the operator lists it in OAUTH_PROVIDER_PRIVATE_HOSTS
 * (an on-premises IdP). That list is an env var on purpose: it is the operator's call,
 * not something an administrator can change through configuration.
 */
export async function assertProviderDestination(
  target: string | URL,
  env: EnvSource = process.env,
) {
  const url = typeof target === 'string' ? new URL(target) : target;

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new OAuthProviderPolicyError(`OAuth provider URL must use https`);
  }

  if (!isProduction(env)) return;

  if (url.protocol !== 'https:') {
    throw new OAuthProviderPolicyError(`OAuth provider URL must use https`);
  }

  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const allowed = privateHostsAllowed(env).has(host);
  const addresses = isIP(unmapIPv4(host))
    ? [host]
    : (await lookup(host, { all: true, verbatim: true })).map((entry) => entry.address);

  for (const address of addresses) {
    if (inList(neverReachable, address) || (inList(nonPublic, address) && !allowed)) {
      throw new OAuthProviderPolicyError(
        `OAuth provider host ${host} resolves to a non-public address`,
      );
    }
  }
}

/**
 * fetch for provider endpoints: the destination is checked first and redirects are not
 * followed, since a redirect would carry the request (and its credentials) to a host
 * that was never checked.
 */
export async function providerFetch(
  target: string | URL,
  init: RequestInit = {},
  env: EnvSource = process.env,
): Promise<Response> {
  await assertProviderDestination(target, env);

  const response = await globalThis.fetch(target, { ...init, redirect: 'manual' });

  if (response.status >= 300 && response.status < 400) {
    throw new OAuthProviderPolicyError(
      `OAuth provider answered with a redirect (${response.status}), which is not followed`,
    );
  }

  return response;
}
