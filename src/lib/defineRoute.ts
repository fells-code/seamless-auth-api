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
import { ErrorSchema, ValidationErrorSchema } from '../schemas/generic.responses.js';
import { AuthTokenType } from '../services/sessionService.js';
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
  deprecated?: boolean;

  auth?: AuthTokenType | undefined;

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

function isZodSchema(value: unknown): value is ZodTypeAny {
  return Boolean(
    value && typeof value === 'object' && typeof (value as ZodTypeAny).safeParse === 'function',
  );
}

/**
 * The stable code a schema-validation failure answers with. Callers branch on this
 * rather than on prose, the same way they do for the codes controllers return.
 */
const VALIDATION_ERROR_CODE = 'invalid_request';

/**
 * Reshapes a `ZodError` into the documented error body.
 *
 * Issues are mapped field by field rather than passed through. A raw `ZodError`
 * serializes to `{ name, message }` with the issues JSON-encoded inside `message`
 * and no `error` key at all, which violates the declared schema and leaves a client
 * with nothing to branch on. Only `path`, `code` and `message` are carried over, so
 * the caller learns which field it got wrong without the response echoing back
 * whatever value it sent.
 */
function toValidationErrorBody(error: ZodError) {
  return {
    error: VALIDATION_ERROR_CODE,
    message: 'Request failed schema validation.',
    details: {
      issues: error.issues.map((issue) => ({
        path: issue.path.filter(
          (segment): segment is string | number =>
            typeof segment === 'string' || typeof segment === 'number',
        ),
        code: issue.code,
        message: issue.message,
      })),
    },
  };
}

/**
 * A route that validates a request can answer `400` from `defineRoute` itself, before
 * its handler runs, so that response has to be documented even though no controller
 * produces it.
 *
 * Only an absent or canonical `ErrorSchema` declaration is replaced. A route that has
 * already declared something richer, such as `AdminValidationErrorSchema`, keeps it:
 * that shape carries `details` of its own and overwriting it would lose detail rather
 * than add any.
 */
function withValidationResponse(
  response: ZodTypeAny | Record<number, ZodTypeAny> | undefined,
  validatesRequest: boolean,
): ZodTypeAny | Record<number, ZodTypeAny> | undefined {
  if (!validatesRequest || (response && isZodSchema(response))) {
    return response;
  }

  const responseMap = (response ?? {}) as Record<number, ZodTypeAny>;
  const declared = responseMap[400];

  if (declared && declared !== ErrorSchema) {
    return response;
  }

  return { ...responseMap, 400: ValidationErrorSchema };
}

function buildResponses(
  response?: ZodTypeAny | Record<number, ZodTypeAny>,
): Record<string, OpenApiResponse> {
  if (!response) {
    return {
      '200': { description: 'Success' },
    };
  }

  if (isZodSchema(response)) {
    return {
      '200': {
        description: 'Success',
        content: {
          'application/json': {
            schema: response,
            example: generateExample(response),
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
  auth: AuthTokenType | undefined,
  middleware: RequestHandler[] | undefined,
): AuthTokenType | undefined {
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
  const { method, path, auth, schemas, summary, description, tags, deprecated, handler } = options;
  const authType = resolveAuthType(auth, options.middleware);

  const params = schemas?.params;
  const query = schemas?.query;
  const body = schemas?.body;
  const response = schemas?.response;
  const validatesRequest = Boolean(params || query || body);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const basePath = (router as any).__basePath ?? '';

  registry.registerPath({
    method,
    path: expressToOpenAPI(`${basePath}${path}`),
    summary,
    description,
    tags,
    deprecated,
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
    responses: buildResponses(withValidationResponse(response, validatesRequest)),
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
      if (error instanceof ZodError) {
        return res.status(400).json(toValidationErrorBody(error));
      }

      // Not a validation failure, so it has no place being reported as one.
      return next(error);
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

            if (isZodSchema(response)) {
              schema = response;
            } else {
              schema = (response as Record<number, ZodTypeAny>)[status];
            }

            if (schema) {
              const parsed = schema.parse(data);
              return originalJson(parsed);
            }

            return originalJson(data);
          } catch (err) {
            // A response that violates its own schema is a server-side drift bug. Log it
            // for observability, but do not overwrite the controller's response or leak
            // internal schema issues to the client: the handler's payload is the source of
            // truth for the client contract.
            logger.error('Response schema validation failed', {
              path,
              status: res.statusCode,
              issues: err instanceof ZodError ? err.issues : err,
            });

            return originalJson(data);
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
