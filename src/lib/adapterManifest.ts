/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { z, ZodTypeAny } from 'zod';

import { getPackageVersion } from '../openapi/document.js';
import {
  AdapterManifestRouteSchema,
  AdapterManifestSchema,
} from '../schemas/adapterManifest.responses.js';
import { AuthTokenType } from '../services/sessionService.js';
import { expressToOpenAPI } from './convertPath.js';

export type AdapterManifestRoute = z.infer<typeof AdapterManifestRouteSchema>;
export type AdapterManifest = z.infer<typeof AdapterManifestSchema>;
export type AdapterCredential = AdapterManifestRoute['credential'];

/**
 * What a route declares in `defineRoute`. `issues: 'session'` stores access and
 * refresh; `issues: 'access'` reissues access without rotating refresh. `body.pick`
 * applies to the adapter's cookie transport only.
 */
export type AdapterRouteDeclaration =
  | false
  | (Partial<Pick<AdapterManifestRoute, 'credential'>> &
      Omit<AdapterManifestRoute, 'method' | 'path' | 'credential'>);

/**
 * The tokens a server adapter holds on the caller's behalf. The API only knows
 * `ephemeral` and `access`, so which slot an ephemeral route reads is something only
 * the route can say: signup and sign-in both run on ephemeral tokens, and an adapter
 * that mixed them up would hand a registration token to a login endpoint.
 */
const ALLOWED_CREDENTIALS: Record<AuthTokenType | 'public', AdapterCredential[]> = {
  access: ['access'],
  ephemeral: ['preAuth', 'registration'],
  public: ['none', 'refresh'],
};

const DEFAULT_CREDENTIALS: Record<AuthTokenType | 'public', AdapterCredential | undefined> = {
  access: 'access',
  ephemeral: undefined,
  public: 'none',
};

const routes = new Map<string, AdapterManifestRoute>();

function unwrap(schema: ZodTypeAny): ZodTypeAny[] {
  if (schema instanceof z.ZodObject) {
    return [schema];
  }

  if (schema instanceof z.ZodUnion) {
    return (schema.options as ZodTypeAny[]).flatMap(unwrap);
  }

  if (schema instanceof z.ZodIntersection) {
    return [...unwrap(schema.def.left as ZodTypeAny), ...unwrap(schema.def.right as ZodTypeAny)];
  }

  if (schema instanceof z.ZodPipe) {
    return unwrap(schema.def.in as ZodTypeAny);
  }

  if (
    schema instanceof z.ZodOptional ||
    schema instanceof z.ZodNullable ||
    schema instanceof z.ZodDefault
  ) {
    return unwrap(schema.unwrap() as ZodTypeAny);
  }

  return [];
}

function successSchemas(response: ZodTypeAny | Record<number, ZodTypeAny> | undefined) {
  if (!response) {
    return [];
  }

  if (response instanceof z.ZodType) {
    return [response];
  }

  return Object.entries(response)
    .filter(([status]) => Number(status) >= 200 && Number(status) < 300)
    .map(([, schema]) => schema);
}

/**
 * Whether a success response carries a token, and whether it always does.
 *
 * Only a required token makes `issues` mandatory. The shared `MessageSchema` has an
 * optional `token` for the OTP and magic-link flows that re-mint the ephemeral token
 * they arrived on, which an adapter already holds and does not need to store again.
 */
export function tokenInResponse(
  response: ZodTypeAny | Record<number, ZodTypeAny> | undefined,
): 'required' | 'optional' | 'none' {
  const fields = successSchemas(response)
    .flatMap(unwrap)
    .map((schema) => (schema as z.ZodObject).shape.token as ZodTypeAny | undefined)
    .filter((field): field is ZodTypeAny => field !== undefined);

  if (fields.some((field) => !(field instanceof z.ZodOptional))) {
    return 'required';
  }

  return fields.length > 0 ? 'optional' : 'none';
}

function normalizePath(path: string) {
  const openApiPath = expressToOpenAPI(path);

  return openApiPath.length > 1 ? openApiPath.replace(/\/+$/, '') : openApiPath;
}

interface RegisterAdapterRouteInput {
  method: string;
  path: string;
  auth: AuthTokenType | undefined;
  adapter: AdapterRouteDeclaration | undefined;
  response: ZodTypeAny | Record<number, ZodTypeAny> | undefined;
}

/**
 * Validates a route's adapter declaration and records it for the manifest.
 *
 * Throws at registration, the way a missing decoy does. Every rule here guards a
 * failure that is silent in an adapter: a public route exposed by accident, an
 * ephemeral route reading the wrong token, or a route that issues a session the
 * adapter never stores.
 */
export function registerAdapterRoute({
  method,
  path,
  auth,
  adapter,
  response,
}: RegisterAdapterRouteInput): void {
  const label = `Route ${method.toUpperCase()} ${path}`;
  const key = `${method.toUpperCase()} ${normalizePath(path)}`;

  if (adapter === false) {
    routes.delete(key);
    return;
  }

  if (!auth && adapter === undefined) {
    throw new Error(
      `${label} takes no token but declares no adapter behaviour. Public routes must say ` +
        'whether server adapters expose them (`adapter: false` or an adapter object).',
    );
  }

  const options = adapter ?? {};
  const scope = auth ?? 'public';
  const credential = options.credential ?? DEFAULT_CREDENTIALS[scope];

  if (!credential) {
    throw new Error(
      `${label} accepts an ephemeral token but declares no adapter credential. ` +
        "Say which token the adapter sends: 'preAuth' or 'registration'.",
    );
  }

  if (!ALLOWED_CREDENTIALS[scope].includes(credential)) {
    throw new Error(
      `${label} is a ${scope} route and cannot use adapter credential '${credential}'. ` +
        `Allowed: ${ALLOWED_CREDENTIALS[scope].join(', ')}.`,
    );
  }

  const token = tokenInResponse(response);

  if (token === 'required' && !options.issues) {
    throw new Error(
      `${label} returns a token but declares no adapter \`issues\`. An adapter would ` +
        'pass the token through instead of storing it.',
    );
  }

  if (options.issues && token === 'none') {
    throw new Error(
      `${label} declares adapter \`issues\` but no success response schema has a token.`,
    );
  }

  if (options.body && !options.issues) {
    throw new Error(`${label} declares an adapter body \`pick\` but issues nothing.`);
  }

  routes.set(key, {
    method: method.toUpperCase() as AdapterManifestRoute['method'],
    path: normalizePath(path),
    credential,
    ...(options.issues ? { issues: options.issues } : {}),
    ...(options.clears ? { clears: options.clears } : {}),
    ...(options.body ? { body: options.body } : {}),
    ...(options.delivery ? { delivery: options.delivery } : {}),
  });
}

export function getAdapterManifest(): AdapterManifest {
  return {
    schemaVersion: 1,
    apiVersion: getPackageVersion(),
    session: {
      subject: 'sub',
      token: 'token',
      refreshToken: 'refreshToken',
      ttl: 'ttl',
      refreshTtl: 'refreshTtl',
    },
    routes: [...routes.values()].sort(
      (a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
    ),
  };
}

export function resetAdapterManifest() {
  routes.clear();
}
