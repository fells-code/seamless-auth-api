/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  OidcAccountClaimsSchema,
  OidcAccountIdParamsSchema,
  OidcAuthContextSchema,
  OidcClientIdParamsSchema,
  OidcClientMetadataSchema,
  OidcEdgeConfigResponseSchema,
  OidcEdgeEventSchema,
  OidcJwksResponseSchema,
  OidcPayloadGrantParamsSchema,
  OidcPayloadParamsSchema,
  OidcPayloadRecordSchema,
  OidcPayloadUidParamsSchema,
  OidcPayloadUpsertRequestSchema,
  OidcPayloadUpsertResponseSchema,
  OidcPayloadUserCodeParamsSchema,
  OidcSessionIdParamsSchema,
  OidcSessionRevokeRequestSchema,
  OidcSignRefusalSchema,
  OidcSignRequestSchema,
  OidcSignResponseSchema,
  OidcVerifySecretRequestSchema,
  OidcVerifySecretResponseSchema,
} from '@seamless-auth/types';

import {
  deleteOidcPayload,
  deleteOidcPayloadsByGrant,
  getOidcAccount,
  getOidcClient,
  getOidcEdgeConfig,
  getOidcJwks,
  getOidcPayload,
  getOidcPayloadByUid,
  getOidcPayloadByUserCode,
  getOidcSessionAuthContext,
  postOidcEvent,
  postOidcPayloadConsume,
  postOidcSessionRevoke,
  postOidcSign,
  postOidcVerifySecret,
  putOidcPayload,
} from '../controllers/oidcEdge.js';
import { createRouter } from '../lib/createRouter.js';
import {
  oidcEventLimiter,
  oidcPayloadWriteLimiter,
  oidcSignLimiter,
  requireOidcEdge,
} from '../middleware/requireOidcEdge.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';

/**
 * Service-token routes for the OpenID Provider service (ADR 0001, D2). Despite the path,
 * these are not the public OIDC endpoints, which the provider service serves itself.
 */
const oidcRouter = createRouter('/oidc');

const edge = {
  adapter: false as const,
  tags: ['OpenID Provider service'],
  middleware: [requireOidcEdge],
};

const guarded = { 401: ErrorSchema, 404: ErrorSchema };

oidcRouter.get(
  '/config',
  {
    ...edge,
    summary: 'Provider settings and the contract version the API speaks',
    schemas: { response: { 200: OidcEdgeConfigResponseSchema, ...guarded } },
  },
  getOidcEdgeConfig,
);

oidcRouter.put(
  '/payloads/:model/:id',
  {
    ...edge,
    middleware: [requireOidcEdge, oidcPayloadWriteLimiter],
    summary: 'Store a provider record',
    schemas: {
      params: OidcPayloadParamsSchema,
      body: OidcPayloadUpsertRequestSchema,
      response: { 200: OidcPayloadUpsertResponseSchema, 400: ErrorSchema, ...guarded },
    },
  },
  putOidcPayload,
);

oidcRouter.get(
  '/payloads/:model/:id',
  {
    ...edge,
    summary: 'Read a provider record',
    schemas: {
      params: OidcPayloadParamsSchema,
      response: { 200: OidcPayloadRecordSchema, ...guarded },
    },
  },
  getOidcPayload,
);

oidcRouter.get(
  '/payloads/:model/by-user-code/:userCode',
  {
    ...edge,
    summary: 'Read a provider record by device user code',
    schemas: {
      params: OidcPayloadUserCodeParamsSchema,
      response: { 200: OidcPayloadRecordSchema, ...guarded },
    },
  },
  getOidcPayloadByUserCode,
);

oidcRouter.get(
  '/payloads/:model/by-uid/:uid',
  {
    ...edge,
    summary: 'Read a provider record by uid',
    schemas: {
      params: OidcPayloadUidParamsSchema,
      response: { 200: OidcPayloadRecordSchema, ...guarded },
    },
  },
  getOidcPayloadByUid,
);

oidcRouter.post(
  '/payloads/:model/:id/consume',
  {
    ...edge,
    summary: 'Mark a provider record consumed',
    schemas: { params: OidcPayloadParamsSchema, response: guarded },
  },
  postOidcPayloadConsume,
);

oidcRouter.delete(
  '/payloads/:model/:id',
  {
    ...edge,
    summary: 'Delete a provider record',
    schemas: { params: OidcPayloadParamsSchema, response: guarded },
  },
  deleteOidcPayload,
);

oidcRouter.delete(
  '/payloads/:model/by-grant/:grantId',
  {
    ...edge,
    summary: 'Delete every record of a model for a grant',
    schemas: { params: OidcPayloadGrantParamsSchema, response: guarded },
  },
  deleteOidcPayloadsByGrant,
);

oidcRouter.post(
  '/sign',
  {
    ...edge,
    middleware: [requireOidcEdge, oidcSignLimiter],
    summary: 'Sign a provider token the API would issue itself',
    schemas: {
      body: OidcSignRequestSchema,
      response: {
        200: OidcSignResponseSchema,
        400: OidcSignRefusalSchema,
        403: OidcSignRefusalSchema,
        ...guarded,
      },
    },
  },
  postOidcSign,
);

oidcRouter.get(
  '/jwks',
  {
    ...edge,
    summary: 'Provider public keys',
    schemas: { response: { 200: OidcJwksResponseSchema, ...guarded } },
  },
  getOidcJwks,
);

oidcRouter.get(
  '/clients/:id',
  {
    ...edge,
    summary: 'Provider client metadata',
    schemas: {
      params: OidcClientIdParamsSchema,
      response: { 200: OidcClientMetadataSchema, ...guarded },
    },
  },
  getOidcClient,
);

oidcRouter.post(
  '/clients/:id/verify-secret',
  {
    ...edge,
    summary: 'Check a shared client secret',
    schemas: {
      params: OidcClientIdParamsSchema,
      body: OidcVerifySecretRequestSchema,
      response: { 200: OidcVerifySecretResponseSchema, ...guarded },
    },
  },
  postOidcVerifySecret,
);

oidcRouter.get(
  '/accounts/:id',
  {
    ...edge,
    summary: 'Claims for a user',
    schemas: {
      params: OidcAccountIdParamsSchema,
      response: { 200: OidcAccountClaimsSchema, ...guarded },
    },
  },
  getOidcAccount,
);

oidcRouter.get(
  '/sessions/:id/auth-context',
  {
    ...edge,
    summary: 'What a session proved, with the derived acr and amr',
    schemas: {
      params: OidcSessionIdParamsSchema,
      response: { 200: OidcAuthContextSchema, ...guarded },
    },
  },
  getOidcSessionAuthContext,
);

oidcRouter.post(
  '/sessions/:id/revoke',
  {
    ...edge,
    summary: 'Revoke the session behind a provider sign-in',
    schemas: {
      params: OidcSessionIdParamsSchema,
      body: OidcSessionRevokeRequestSchema,
      response: guarded,
    },
  },
  postOidcSessionRevoke,
);

oidcRouter.post(
  '/events',
  {
    ...edge,
    middleware: [requireOidcEdge, oidcEventLimiter],
    summary: 'Record a provider audit event',
    schemas: {
      body: OidcEdgeEventSchema,
      response: { 202: MessageSchema, 400: ErrorSchema, ...guarded },
    },
  },
  postOidcEvent,
);

export default oidcRouter.router;
