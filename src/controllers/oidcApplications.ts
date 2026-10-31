/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { OidcApplicationKeysRequest } from '@seamless-auth/types';
import { Request, Response } from 'express';

import { toValidationErrorBody } from '../lib/defineRoute.js';
import type { AuthEventType } from '../schemas/authEvent.types.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  createOidcApplication,
  deleteOidcApplication,
  findOidcApplication,
  listOidcApplications,
  OidcApplicationError,
  OidcApplicationInvalidError,
  rotateOidcApplicationSecret,
  serializeOidcApplication,
  setOidcApplicationKeys,
  updateOidcApplication,
} from '../services/oidcApplicationService.js';
import { AuthenticatedRequest } from '../types/types.js';

function audit(req: Request, event: { type: AuthEventType; metadata: Record<string, unknown> }) {
  return AuthEventService.log({
    actorUserId: (req as AuthenticatedRequest).user?.id ?? null,
    req,
    ...event,
  });
}

function sendError(res: Response, error: unknown) {
  if (error instanceof OidcApplicationError) {
    return res.status(error.status).json({ error: error.message });
  }
  if (error instanceof OidcApplicationInvalidError) {
    return res.status(400).json(toValidationErrorBody(error.zodError));
  }
  throw error;
}

function keysSummary(keys: OidcApplicationKeysRequest) {
  return 'jwks' in keys
    ? { source: 'jwks', kids: keys.jwks.keys.map((key) => key.kid) }
    : { source: 'jwks_uri', jwksUri: keys.jwksUri };
}

export async function listApplications(_req: Request, res: Response) {
  const clients = await listOidcApplications();
  return res.json({ applications: clients.map(serializeOidcApplication) });
}

export async function getApplication(req: Request, res: Response) {
  try {
    const client = await findOidcApplication(req.params.id as string);
    return res.json({ application: serializeOidcApplication(client) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function createApplication(req: Request, res: Response) {
  try {
    const { client, clientSecret } = await createOidcApplication(req.body);
    const application = serializeOidcApplication(client);

    await audit(req, {
      type: 'admin_oidc_application_created',
      metadata: {
        clientId: client.id,
        clientType: application.clientType,
        firstParty: application.firstParty,
        tokenEndpointAuthMethod: application.tokenEndpointAuthMethod,
        grantTypes: application.grantTypes,
        deviceFlowEnabled: application.deviceFlowEnabled,
        pkceRequired: application.pkceRequired,
        redirectUris: application.redirectUris,
      },
    });

    if (!application.pkceRequired) {
      await audit(req, {
        type: 'admin_oidc_application_pkce_updated',
        metadata: { clientId: client.id, pkceRequired: false },
      });
    }

    return res.status(201).json({ application, ...(clientSecret ? { clientSecret } : {}) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function updateApplication(req: Request, res: Response) {
  try {
    const pkceBefore = (await findOidcApplication(req.params.id as string)).pkceRequired;
    const client = await updateOidcApplication(req.params.id as string, req.body);

    if (client.pkceRequired !== pkceBefore) {
      await audit(req, {
        type: 'admin_oidc_application_pkce_updated',
        metadata: { clientId: client.id, pkceRequired: client.pkceRequired },
      });
    }

    await audit(req, {
      type: 'admin_oidc_application_updated',
      metadata: {
        clientId: client.id,
        changed: Object.keys(req.body).sort(),
        ...req.body,
      },
    });

    return res.json({ application: serializeOidcApplication(client) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function putApplicationKeys(req: Request, res: Response) {
  try {
    const client = await setOidcApplicationKeys(req.params.id as string, req.body);

    await audit(req, {
      type: 'admin_oidc_application_keys_updated',
      metadata: {
        clientId: client.id,
        ...keysSummary(req.body),
      },
    });

    return res.json({ application: serializeOidcApplication(client) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function rotateApplicationSecret(req: Request, res: Response) {
  try {
    const { client, clientSecret } = await rotateOidcApplicationSecret(req.params.id as string);

    await audit(req, {
      type: 'admin_oidc_application_secret_rotated',
      metadata: { clientId: client.id },
    });

    return res.json({ application: serializeOidcApplication(client), clientSecret });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function deleteApplication(req: Request, res: Response) {
  try {
    const id = req.params.id as string;
    await deleteOidcApplication(id);

    await audit(req, { type: 'admin_oidc_application_deleted', metadata: { clientId: id } });

    return res.json({ message: 'Application deleted' });
  } catch (error) {
    return sendError(res, error);
  }
}
