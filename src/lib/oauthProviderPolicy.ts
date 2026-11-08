/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { LookupAddress } from 'node:dns';
import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';

import { missingOAuthProviderEndpoints } from '@seamless-auth/types';

import type { OAuthProviderConfig } from '../schemas/systemConfig.schema.js';
import { inList, neverReachable, nonPublic, unmapIPv4 } from './outboundAddress.js';
import { sendProviderRequest } from './providerTransport.js';

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

function addressAllowed(address: string, hostAllowlisted: boolean) {
  return !inList(neverReachable, address) && (hostAllowlisted || !inList(nonPublic, address));
}

export function isNonPublicAddress(address: string) {
  return inList(nonPublic, address);
}

function isProduction(env: EnvSource) {
  return env.NODE_ENV === 'production';
}

/**
 * Outside production any host may be private, so a local stack can reach a provider on a
 * private address. The never-reachable ranges stay closed in every mode, since a staging
 * deployment runs on the same cloud metadata network as a production one.
 */
function hostMayBePrivate(hostname: string, env: EnvSource) {
  return !isProduction(env) || privateHostsAllowed(env).has(hostname.toLowerCase());
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
  const problems: string[] = missingOAuthProviderEndpoints(provider).map(
    (field) => `${field} is required unless the provider has an issuer to discover it from`,
  );

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
 * Checks a provider URL before a request: http(s) only, https in production, and in
 * production an IP literal must be public. A literal never goes through DNS, so
 * `guardedLookup` would not see it.
 */
export function assertProviderDestination(target: string | URL, env: EnvSource = process.env) {
  const url = typeof target === 'string' ? new URL(target) : target;

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new OAuthProviderPolicyError('OAuth provider URL must use https');
  }

  if (isProduction(env) && url.protocol !== 'https:') {
    throw new OAuthProviderPolicyError('OAuth provider URL must use https');
  }

  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (isIP(unmapIPv4(host)) && !addressAllowed(host, hostMayBePrivate(host, env))) {
    throw new OAuthProviderPolicyError(`OAuth provider host ${host} is a non-public address`);
  }

  return url;
}

type LookupCallback = (
  error: Error | null,
  address: string | LookupAddress[],
  family?: number,
) => void;

/**
 * DNS for the provider connection itself. The host must resolve only to public
 * addresses unless the operator lists it in OAUTH_PROVIDER_PRIVATE_HOSTS (an
 * on-premises IdP); that list is an env var on purpose, so it is the operator's call
 * and not something configuration can change. Checking here rather than before the
 * request means the addresses checked are the ones the socket connects to, so a name
 * cannot answer one way for the check and another for the connection.
 */
export function guardedLookup(env: EnvSource = process.env): LookupFunction {
  const guarded = (
    hostname: string,
    options: { family?: number | string; all?: boolean },
    callback: LookupCallback,
  ) => {
    const family =
      options.family === 6 || options.family === 'IPv6'
        ? 6
        : options.family === 4 || options.family === 'IPv4'
          ? 4
          : 0;

    lookup(hostname, { all: true, verbatim: true, family }).then(
      (addresses) => {
        const allowed = hostMayBePrivate(hostname, env);
        if (
          addresses.length === 0 ||
          addresses.some((entry) => !addressAllowed(entry.address, allowed))
        ) {
          callback(
            new OAuthProviderPolicyError(
              `OAuth provider host ${hostname} resolves to a non-public address`,
            ),
            [],
          );
          return;
        }

        if (options.all) {
          callback(null, addresses);
        } else {
          callback(null, addresses[0].address, addresses[0].family);
        }
      },
      (error: Error) => callback(error, []),
    );
  };

  return guarded as unknown as LookupFunction;
}

const MAX_PROVIDER_RESPONSE_BYTES = 1024 * 1024;
const PROVIDER_TIMEOUT_MS = 10_000;
// node:https sends no User-Agent of its own, unlike fetch, and GitHub's API
// answers any request without one with 403.
const PROVIDER_USER_AGENT = 'seamless-auth-api';

export function guardedRequest(url: URL, init: RequestInit, env: EnvSource): Promise<Response> {
  const headers = Object.fromEntries(new Headers(init.headers ?? {}).entries());
  headers['user-agent'] ??= PROVIDER_USER_AGENT;
  const body = init.body == null ? undefined : String(init.body);
  if (body !== undefined) headers['content-length'] = String(Buffer.byteLength(body));

  const send = url.protocol === 'https:' ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    const request = send(
      url,
      {
        method: init.method ?? 'GET',
        headers,
        lookup: guardedLookup(env),
        timeout: PROVIDER_TIMEOUT_MS,
        signal: init.signal ?? undefined,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;

        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_PROVIDER_RESPONSE_BYTES) {
            response.destroy(new OAuthProviderPolicyError('OAuth provider response is too large'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('error', reject);
        response.on('end', () => {
          const status = response.statusCode ?? 502;
          const answerHeaders = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (value === undefined) continue;
            for (const item of Array.isArray(value) ? value : [value])
              answerHeaders.append(name, item);
          }
          const empty = status === 204 || status === 304;
          resolve(
            new Response(empty ? null : Buffer.concat(chunks), { status, headers: answerHeaders }),
          );
        });
      },
    );

    request.on('timeout', () =>
      request.destroy(new OAuthProviderPolicyError('OAuth provider request timed out')),
    );
    request.on('error', reject);
    request.end(body);
  });
}

/**
 * fetch for provider endpoints. Redirects are not followed, since a redirect would
 * carry the request (and its credentials) to a host that was never checked. Every
 * request goes through `guardedLookup`, which outside production admits private
 * addresses, so local stacks can reach a provider on one, but never link-local or
 * unspecified ones.
 */
export async function providerFetch(
  target: string | URL,
  init: RequestInit = {},
  env: EnvSource = process.env,
): Promise<Response> {
  const url = assertProviderDestination(target, env);

  const response = await sendProviderRequest(url, init, env);

  if (response.status >= 300 && response.status < 400) {
    throw new OAuthProviderPolicyError(
      `OAuth provider answered with a redirect (${response.status}), which is not followed`,
    );
  }

  return response;
}
