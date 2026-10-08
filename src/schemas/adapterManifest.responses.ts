/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

const AdapterHeldSchema = z.enum(['preAuth', 'registration', 'access', 'refresh']);

export const AdapterManifestRouteSchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
  path: z.string(),
  credential: z.enum(['none', 'preAuth', 'registration', 'access', 'refresh']),
  issues: z.enum(['preAuth', 'registration', 'session', 'access']).optional(),
  clears: z.array(AdapterHeldSchema).optional(),
  body: z.object({ pick: z.array(z.string()) }).optional(),
  delivery: z.literal(true).optional(),
});

export const AdapterManifestSchema = z.object({
  schemaVersion: z.literal(1),
  apiVersion: z.string(),
  session: z.object({
    subject: z.literal('sub'),
    token: z.literal('token'),
    refreshToken: z.literal('refreshToken'),
    ttl: z.literal('ttl'),
    refreshTtl: z.literal('refreshTtl'),
  }),
  routes: z.array(AdapterManifestRouteSchema),
});
