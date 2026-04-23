/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { NextFunction, RequestHandler, Response, Router } from 'express';
import { ZodError, ZodTypeAny } from 'zod';

import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import {
  AuthAwareRequestHandler,
  getSecuritySchemeName,
} from '../middleware/attachAuthMiddleware.js';
import { registry } from '../openapi/registry.js';
import { CookieType } from '../services/sessionService.js';
import getLogger from '../utils/logger.js';
import { expressToOpenAPI } from './convertPath.js';
import { InferRequest, RouteSchemas } from './routeTypes.js';
import { generateExample } from './zodExample.js';

const logger = getLogger('defineRoute');

type HttpMethod = 'get' | 'post' | 'put' | 'patch' | 'delete';

interface DefineRouteOptions<S extends RouteSchemas> {
  method: HttpMethod;
  path: string;
  middleware?: RequestHandler[];
  summary?: string;
  description?: string;
  tags?: string[];

  auth?: CookieType | undefined;

  schemas?: S;

  handler: (req: InferRequest<S>, res: Response, next: NextFunction) => Promise<void> | void;
}

type OpenApiResponse = {
  description: string;
  content?: {
    'application/json': {
      schema: ZodTypeAny;
      example?: unknown;
    };
  };
};

function buildResponses(
  response?: ZodTypeAny | Record<number, ZodTypeAny>,
): Record<string, OpenApiResponse> {
  if (!response) {
    return {
      '200': { description: 'Success' },
    };
  }

  if (!(response instanceof Object)) {
    const schema = response as ZodTypeAny;

    return {
      '200': {
        description: 'Success',
        content: {
          'application/json': {
            schema,
            example: generateExample(schema),
          },
        },
      },
    };
  }

  const responses: Record<string, OpenApiResponse> = {};

  const responseMap = response as Record<number, ZodTypeAny>;

  for (const status of Object.keys(responseMap)) {
    const schema = responseMap[Number(status)];

    responses[status] = {
      description: `HTTP ${status}`,
      content: {
        'application/json': {
          schema,
          example: generateExample(schema),
        },
      },
    };
  }

  return responses;
}

function resolveAuthType(
  auth: CookieType | undefined,
  middleware: RequestHandler[] | undefined,
): CookieType | undefined {
  if (auth) {
    return auth;
  }

  for (const handler of middleware ?? []) {
    const authType = (handler as AuthAwareRequestHandler).seamlessAuthType;

    if (authType) {
      return authType;
    }
  }

  return undefined;
}

export function defineRoute<S extends RouteSchemas>(
  router: Router,
  options: DefineRouteOptions<S>,
): void {
  const { method, path, auth, schemas, summary, description, tags, handler } = options;
  const authType = resolveAuthType(auth, options.middleware);

  const params = schemas?.params;
  const query = schemas?.query;
  const body = schemas?.body;
  const response = schemas?.response;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const basePath = (router as any).__basePath ?? '';

  registry.registerPath({
    method,
    path: expressToOpenAPI(`${basePath}${path}`),
    summary,
    description,
    tags,
    security: authType ? [{ [getSecuritySchemeName(authType)]: [] }] : undefined,
    request: {
      params,
      query,
      body: body
        ? {
            content: {
              'application/json': { schema: body },
            },
          }
        : undefined,
    },
    responses: buildResponses(response),
  });

  const validate: RequestHandler = (req, res, next) => {
    try {
      if (params) {
        req.params = params.parse(req.params) as typeof req.params;
      }

      if (query) {
        req.query = query.parse(req.query) as typeof req.query;
      }

      if (body) {
        req.body = body.parse(req.body) as typeof req.body;
      }

      return next();
    } catch (error: unknown) {
      return res.status(400).json(error);
    }
  };

  const wrappedHandler: RequestHandler = async (req, res, next) => {
    try {
      const originalJson = res.json.bind(res);

      if (response) {
        res.json = ((data: unknown) => {
          try {
            const status = res.statusCode || 200;

            let schema: ZodTypeAny | undefined;

            if (typeof response === 'object') {
              schema = (response as Record<number, ZodTypeAny>)[status];
            } else {
              schema = response;
            }

            if (schema) {
              const parsed = schema.parse(data);
              return originalJson(parsed);
            }

            return originalJson(data);
          } catch (err) {
            logger.error('Response schema validation failed', err);

            return originalJson({
              error: 'Response validation failed',
              issues: err instanceof ZodError ? err.issues : err,
            });
          }
        }) as typeof res.json;
      }
      await Promise.resolve(handler(req as InferRequest<S>, res, next));
    } catch (error: unknown) {
      logger.error(`Error wrapping parsed handler. ${error}`);
      return next(error);
    }
  };

  const middlewareStack: RequestHandler[] = [];

  if (auth) {
    middlewareStack.push(attachAuthMiddleware(auth));
  }

  if (options.middleware) {
    middlewareStack.push(...options.middleware);
  }

  middlewareStack.push(validate);
  middlewareStack.push(wrappedHandler);

  router[method](path, ...middlewareStack);
}
