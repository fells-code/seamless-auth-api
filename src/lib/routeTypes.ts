/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { Request } from 'express';
import { z, ZodObject, ZodRawShape, ZodTypeAny } from 'zod';

export type RouteResponseSchemas = {
  [status: number]: ZodTypeAny;
};

export type RouteSchemas = {
  params?: ZodObject<ZodRawShape>;
  query?: ZodObject<ZodRawShape>;
  body?: ZodTypeAny;
  response?: ZodTypeAny | RouteResponseSchemas;
};

export type InferRequest<S extends RouteSchemas> = Request<
  S['params'] extends ZodObject<ZodRawShape> ? z.infer<S['params']> : Record<string, never>,
  unknown,
  S['body'] extends ZodTypeAny ? z.infer<S['body']> : Record<string, never>,
  S['query'] extends ZodObject<ZodRawShape> ? z.infer<S['query']> : Record<string, never>
>;
