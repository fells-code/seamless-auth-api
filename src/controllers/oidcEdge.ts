/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  OIDC_EDGE_CONTRACT_VERSION,
  type OidcAccountIdParams,
  type OidcClientIdParams,
  type OidcEdgeEvent,
  type OidcEdgeEventType,
  type OidcPayloadGrantParams,
  type OidcPayloadParams,
  type OidcPayloadUidParams,
  type OidcPayloadUpsertRequest,
  type OidcPayloadUserCodeParams,
  type OidcSessionIdParams,
  type OidcSessionRevokeRequest,
  type OidcSignRequest,
  type OidcVerifySecretRequest,
} from '@seamless-auth/types';
import { Request, Response } from 'express';

import { getSystemConfig } from '../config/getSystemConfig.js';
import { OidcPayload } from '../models/oidcPayloads.js';
import { Session } from '../models/sessions.js';
import type { AuthEventType } from '../schemas/authEvent.types.js';
import { AuthEventService } from '../services/authEventService.js';
import { getOidcAuthContext, isUuid } from '../services/oidcAuthContext.js';
import {
  getOidcAccountClaims,
  getOidcClientMetadata,
  verifyOidcClientSecret,
} from '../services/oidcClientRegistry.js';
import {
  consumeOidcPayload,
  destroyOidcPayload,
  findOidcPayload,
  findOidcPayloadByUid,
  findOidcPayloadByUserCode,
  InvalidSessionIdError,
  revokeOidcPayloadsByGrant,
  upsertOidcPayload,
} from '../services/oidcPayloadStore.js';
import { getOidcPublicJwks } from '../services/oidcProviderKeys.js';
import { signForOidcEdge } from '../services/oidcSigning.js';
import { revokeSessionChain } from '../services/sessionService.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('oidcEdge');

type Req<P = Record<string, string>, B = unknown> = Request<P, unknown, B>;

const NOT_FOUND = { error: 'not_found' };

// Spelled out rather than built from a template, so adding an edge event type is a compile
// error here until it has an auth event type of its own.
const EDGE_EVENT_TYPES: Record<OidcEdgeEventType, { type: AuthEventType }> = {
  interaction_completed: { type: 'oidc_interaction_completed' },
  consent_granted: { type: 'oidc_consent_granted' },
  consent_denied: { type: 'oidc_consent_denied' },
  token_issued: { type: 'oidc_token_issued' },
  token_refreshed: { type: 'oidc_token_refreshed' },
  refresh_token_suspicious: { type: 'oidc_refresh_token_suspicious' },
  token_revoked: { type: 'oidc_token_revoked' },
  client_auth_failed: { type: 'oidc_client_auth_failed' },
  end_session: { type: 'oidc_end_session' },
  device_code_approved: { type: 'oidc_device_code_approved' },
  device_code_denied: { type: 'oidc_device_code_denied' },
  edge_failed: { type: 'oidc_edge_failed' },
};

export async function getOidcEdgeConfig(_req: Request, res: Response) {
  const config = await getSystemConfig();

  return res.status(200).json({
    contractVersion: OIDC_EDGE_CONTRACT_VERSION,
    issuer: config.oidc_issuer,
    appName: config.app_name,
    allowClientSecrets: config.allow_client_secrets,
    thirdPartyClientsEnabled: config.third_party_clients_enabled,
  });
}

export async function putOidcPayload(
  req: Req<OidcPayloadParams, OidcPayloadUpsertRequest>,
  res: Response,
) {
  try {
    const result = await upsertOidcPayload(req.params.model, req.params.id, req.body);
    return res.status(200).json(result);
  } catch (error) {
    if (error instanceof InvalidSessionIdError) {
      return res.status(400).json({ error: 'invalid_session_id', message: error.message });
    }
    throw error;
  }
}

export async function getOidcPayload(req: Req<OidcPayloadParams>, res: Response) {
  const record = await findOidcPayload(req.params.model, req.params.id);
  return record ? res.status(200).json(record) : res.status(404).json(NOT_FOUND);
}

export async function getOidcPayloadByUserCode(req: Req<OidcPayloadUserCodeParams>, res: Response) {
  const record = await findOidcPayloadByUserCode(req.params.model, req.params.userCode);
  return record ? res.status(200).json(record) : res.status(404).json(NOT_FOUND);
}

export async function getOidcPayloadByUid(req: Req<OidcPayloadUidParams>, res: Response) {
  const record = await findOidcPayloadByUid(req.params.model, req.params.uid);
  return record ? res.status(200).json(record) : res.status(404).json(NOT_FOUND);
}

export async function postOidcPayloadConsume(req: Req<OidcPayloadParams>, res: Response) {
  await consumeOidcPayload(req.params.model, req.params.id);
  return res.status(204).end();
}

export async function deleteOidcPayload(req: Req<OidcPayloadParams>, res: Response) {
  await destroyOidcPayload(req.params.model, req.params.id);
  return res.status(204).end();
}

export async function deleteOidcPayloadsByGrant(req: Req<OidcPayloadGrantParams>, res: Response) {
  await revokeOidcPayloadsByGrant(req.params.model, req.params.grantId);
  return res.status(204).end();
}

export async function postOidcSign(
  req: Req<Record<string, string>, OidcSignRequest>,
  res: Response,
) {
  const outcome = await signForOidcEdge(req.body);

  if (outcome.ok) {
    return res.status(200).json({ kid: outcome.kid, signature: outcome.signature });
  }

  await AuthEventService.log({
    userId: outcome.userId ?? null,
    sessionId: req.body.sessionId ?? null,
    type: 'oidc_sign_failed',
    req,
    metadata: { reason: outcome.code, kind: req.body.kind, clientId: req.body.clientId },
  });

  const status = outcome.code === 'malformed_signing_input' ? 400 : 403;
  return res.status(status).json({ error: outcome.code });
}

export async function getOidcJwks(_req: Request, res: Response) {
  return res.status(200).json(getOidcPublicJwks());
}

export async function getOidcClient(req: Req<OidcClientIdParams>, res: Response) {
  const metadata = await getOidcClientMetadata(req.params.id);
  return metadata ? res.status(200).json(metadata) : res.status(404).json(NOT_FOUND);
}

export async function postOidcVerifySecret(
  req: Req<OidcClientIdParams, OidcVerifySecretRequest>,
  res: Response,
) {
  const valid = await verifyOidcClientSecret(req.params.id, req.body.secret);
  return res.status(200).json({ valid });
}

export async function getOidcAccount(req: Req<OidcAccountIdParams>, res: Response) {
  const claims = await getOidcAccountClaims(req.params.id);
  return claims ? res.status(200).json(claims) : res.status(404).json(NOT_FOUND);
}

export async function getOidcSessionAuthContext(req: Req<OidcSessionIdParams>, res: Response) {
  const context = await getOidcAuthContext(req.params.id);
  return context ? res.status(200).json(context) : res.status(404).json(NOT_FOUND);
}

export async function postOidcSessionRevoke(
  req: Req<OidcSessionIdParams, OidcSessionRevokeRequest>,
  res: Response,
) {
  const session = isUuid(req.params.id) ? await Session.findByPk(req.params.id) : null;

  if (!session) return res.status(404).json(NOT_FOUND);

  // From the recorded row forward, so the rotations the edge's adapter made since the
  // provider sign-in are revoked with it.
  await revokeSessionChain(session, `oidc_${req.body.reason}`);
  await OidcPayload.destroy({ where: { sessionId: session.id } });

  await AuthEventService.log({
    userId: session.userId,
    sessionId: session.id,
    type: 'oidc_session_revoked',
    req,
    metadata: { reason: req.body.reason, correlationId: req.body.correlationId ?? null },
  });

  logger.info(`Provider revoked session ${session.id} (${req.body.reason})`);
  return res.status(204).end();
}

export async function postOidcEvent(
  req: Req<Record<string, string>, OidcEdgeEvent>,
  res: Response,
) {
  const { type, correlationId, occurredAt, clientId, userId, sessionId, grantId, metadata } =
    req.body;

  await AuthEventService.log({
    userId: userId ?? null,
    sessionId: sessionId ?? null,
    type: EDGE_EVENT_TYPES[type].type,
    req,
    metadata: {
      ...metadata,
      correlationId,
      occurredAt,
      clientId: clientId ?? null,
      grantId: grantId ?? null,
    },
  });

  return res.status(202).json({ message: 'Accepted' });
}
