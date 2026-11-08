/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { LookupAddress } from 'node:dns';
import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { BlockList, isIP, type LookupFunction } from 'node:net';

import type { CalloutFailure } from '@seamless-auth/types';

import { inList, neverReachable, nonPublic, unmapIPv4 } from './outboundAddress.js';

type EnvSource = Record<string, string | undefined>;

/**
 * Hosts on a private address that webhooks, login hooks and audit sinks may reach in production
 * (ADR 0005, D8). An env var, so it is the operator's call: nothing written through the API can
 * widen it. Kept apart from `OAUTH_PROVIDER_PRIVATE_HOSTS`, so allowing an internal hook service
 * does not also allow it as an identity provider.
 */
export const CALLOUT_PRIVATE_HOSTS_ENV = 'CALLOUT_PRIVATE_HOSTS';

// Multicast and broadcast never answer a request, and reaching them is only ever a probe.
const calloutNeverReachable = new BlockList();
calloutNeverReachable.addSubnet('224.0.0.0', 4, 'ipv4');
calloutNeverReachable.addAddress('255.255.255.255', 'ipv4');
calloutNeverReachable.addSubnet('ff00::', 8, 'ipv6');

export class CalloutError extends Error {
  readonly failure: CalloutFailure;

  constructor(failure: CalloutFailure, message: string) {
    super(message);
    this.name = 'CalloutError';
    this.failure = failure;
  }
}

function isProduction(env: EnvSource) {
  return env.NODE_ENV === 'production';
}

function bare(hostname: string) {
  return hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

function privateHostsAllowed(env: EnvSource) {
  return new Set(
    (env[CALLOUT_PRIVATE_HOSTS_ENV] ?? '')
      .split(',')
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
  );
}

function hostMayBePrivate(hostname: string, env: EnvSource) {
  return !isProduction(env) || privateHostsAllowed(env).has(bare(hostname));
}

function addressAllowed(address: string, hostAllowlisted: boolean) {
  return (
    !inList(neverReachable, address) &&
    !inList(calloutNeverReachable, address) &&
    (hostAllowlisted || !inList(nonPublic, address))
  );
}

function issuerHost(env: EnvSource) {
  try {
    return env.ISSUER ? new URL(env.ISSUER).hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** Whether a host may be the target of a callout, before any DNS. */
export function calloutHostProblem(hostname: string, env: EnvSource = process.env): string | null {
  const host = bare(hostname);

  if (!host) return 'has no host';
  if (host === issuerHost(env)) return 'must not point at this server';

  if (isIP(unmapIPv4(host)) && !addressAllowed(host, hostMayBePrivate(host, env))) {
    return isProduction(env) &&
      !inList(neverReachable, host) &&
      !inList(calloutNeverReachable, host)
      ? `points at a non-public address; list the host in ${CALLOUT_PRIVATE_HOSTS_ENV} to allow it`
      : 'points at an address that is never reachable';
  }

  return null;
}

/**
 * What is wrong with a callout URL, for the API to refuse it when written. The same checks run
 * again at connect time, where DNS is also checked.
 */
export function calloutUrlProblem(value: string, env: EnvSource = process.env): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'is not a valid URL';
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') return 'must use https';
  if (isProduction(env) && url.protocol !== 'https:') return 'must use https';
  if (url.username || url.password) return 'must not carry a username or password';

  return calloutHostProblem(url.hostname, env);
}

type LookupCallback = (
  error: Error | null,
  address: string | LookupAddress[],
  family?: number,
) => void;

/**
 * DNS for the callout's own socket, so the addresses checked are the ones connected to and a
 * name cannot answer one way for a check and another for the connection. Every address a name
 * resolves to must be allowed, not just the first.
 */
export function calloutLookup(env: EnvSource = process.env): LookupFunction {
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
          callback(new CalloutError('refused', `${hostname} resolves to a refused address`), []);
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

/** Throws a `refused` CalloutError for a URL no callout may reach. */
export function assertCalloutDestination(target: string, env: EnvSource = process.env): URL {
  const problem = calloutUrlProblem(target, env);
  if (problem) throw new CalloutError('refused', `Callout URL ${problem}`);
  return new URL(target);
}

export type CalloutRequest = {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs: number;
  maxResponseBytes: number;
};

export type CalloutResponse = {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
};

const USER_AGENT = 'seamless-auth-api';

/**
 * One HTTP request to an adopter-supplied URL. Redirects are not followed: a 3xx comes back as a
 * response, and the caller treats it as a failure, since following it would carry a signed body
 * to a host that was never checked.
 */
export function calloutRequest(
  target: string,
  { method = 'POST', headers = {}, body, timeoutMs, maxResponseBytes }: CalloutRequest,
  env: EnvSource = process.env,
): Promise<CalloutResponse> {
  let url: URL;
  try {
    url = assertCalloutDestination(target, env);
  } catch (error) {
    return Promise.reject(error);
  }

  const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
  const outgoing: Record<string, string> = { 'user-agent': USER_AGENT, ...headers };
  if (body !== undefined) outgoing['content-length'] = String(Buffer.byteLength(body));

  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error: CalloutError) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.destroy();
      reject(error);
    };

    const request = send(
      url,
      { method, headers: outgoing, lookup: calloutLookup(env) },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;

        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxResponseBytes) {
            fail(new CalloutError('too_large', 'Callout response is too large'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('error', () =>
          fail(new CalloutError('connection_failed', 'Callout response failed')),
        );
        response.on('end', () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve({
            status: response.statusCode ?? 502,
            headers: response.headers,
            body: Buffer.concat(chunks),
          });
        });
      },
    );

    // A whole-request deadline rather than a socket idle timeout, so a destination that
    // trickles a byte at a time cannot hold a sign-in open.
    const timer = setTimeout(
      () => fail(new CalloutError('timed_out', 'Callout timed out')),
      timeoutMs,
    );
    timer.unref();

    request.on('error', (error: Error) =>
      fail(
        error instanceof CalloutError
          ? error
          : new CalloutError('connection_failed', 'Callout connection failed'),
      ),
    );

    request.end(body);
  });
}
