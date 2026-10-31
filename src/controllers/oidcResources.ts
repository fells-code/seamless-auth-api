/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import type { AuthEventType } from '../schemas/authEvent.types.js';
import { AuthEventService } from '../services/authEventService.js';
import { OidcApplicationError } from '../services/oidcApplicationService.js';
import {
  createOidcResource,
  deleteOidcResource,
  findOidcResource,
  listOidcApplicationResources,
  listOidcResources,
  OidcResourceError,
  serializeOidcResource,
  setOidcApplicationResources,
  updateOidcResource,
} from '../services/oidcResourceService.js';
import { AuthenticatedRequest } from '../types/types.js';

function audit(req: Request, event: { type: AuthEventType; metadata: Record<string, unknown> }) {
  return AuthEventService.log({
    actorUserId: (req as AuthenticatedRequest).user?.id ?? null,
    req,
    ...event,
  });
}

function sendError(res: Response, error: unknown) {
  if (error instanceof OidcResourceError || error instanceof OidcApplicationError) {
    return res.status(error.status).json({ error: error.message });
  }
  throw error;
}

export async function listResources(_req: Request, res: Response) {
  const resources = await listOidcResources();
  return res.json({ resources: resources.map(serializeOidcResource) });
}

export async function getResource(req: Request, res: Response) {
  try {
    const resource = await findOidcResource(req.params.id as string);
    return res.json({ resource: serializeOidcResource(resource) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function createResource(req: Request, res: Response) {
  try {
    const resource = await createOidcResource(req.body);

    await audit(req, {
      type: 'admin_oidc_resource_created',
      metadata: {
        resourceId: resource.id,
        identifier: resource.identifier,
        scopes: resource.scopes,
      },
    });

    return res.status(201).json({ resource: serializeOidcResource(resource) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function updateResource(req: Request, res: Response) {
  try {
    const resource = await updateOidcResource(req.params.id as string, req.body);

    await audit(req, {
      type: 'admin_oidc_resource_updated',
      metadata: {
        resourceId: resource.id,
        identifier: resource.identifier,
        changed: Object.keys(req.body).sort(),
        ...req.body,
      },
    });

    return res.json({ resource: serializeOidcResource(resource) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function deleteResource(req: Request, res: Response) {
  try {
    const id = req.params.id as string;
    await deleteOidcResource(id);

    await audit(req, { type: 'admin_oidc_resource_deleted', metadata: { resourceId: id } });

    return res.json({ message: 'Resource deleted' });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function getApplicationResources(req: Request, res: Response) {
  try {
    const resources = await listOidcApplicationResources(req.params.id as string);
    return res.json({ resources });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function putApplicationResources(req: Request, res: Response) {
  try {
    const clientId = req.params.id as string;
    const resources = await setOidcApplicationResources(clientId, req.body);

    await audit(req, {
      type: 'admin_oidc_application_resources_updated',
      metadata: {
        clientId,
        resources: resources.map(({ identifier, scopes }) => ({ identifier, scopes })),
      },
    });

    return res.json({ resources });
  } catch (error) {
    return sendError(res, error);
  }
}
