/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { NextFunction, RequestHandler, Response, Router } from 'express';
import { ZodTypeAny } from 'zod';

import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware.js';
import { registry } from '../openapi/registry.js';
import { CookieType } from '../services/sessionService.js';
import { expressToOpenAPI } from './convertPath.js';
import { InferRequest, RouteSchemas } from './routeTypes.js';
import { generateExample } from './zodExample.js';

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

  if (!(response instanceof Object) || !('200' in response)) {
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

export function defineRoute<S extends RouteSchemas>(
  router: Router,
  options: DefineRouteOptions<S>,
): void {
  const { method, path, auth, schemas, summary, description, tags, handler } = options;

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
    security: auth ? [{ bearerAuth: [] }] : undefined,
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
        const schema =
          typeof response === 'object' && '200' in (response as object)
            ? (response as Record<number, ZodTypeAny>)[200]
            : response;

        if (schema) {
          res.json = ((data: unknown) => {
            const parsed = (schema as ZodTypeAny).parse(data);
            return originalJson(parsed);
          }) as typeof res.json;
        }
      }

      await Promise.resolve(handler(req as InferRequest<S>, res, next));
    } catch (error: unknown) {
      return next(error);
    }
  };

  const middlewareStack: RequestHandler[] = [];

  if (options.middleware) {
    middlewareStack.push(...options.middleware);
  }

  if (auth) {
    middlewareStack.push(attachAuthMiddleware(auth));
  }

  middlewareStack.push(validate);
  middlewareStack.push(wrappedHandler);

  router[method](path, ...middlewareStack);
}
