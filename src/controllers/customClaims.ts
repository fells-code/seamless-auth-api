/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  CUSTOM_CLAIMS_BUDGET_BYTES,
  type CustomClaimSourceKind,
  RESERVED_CLAIM_NAMES,
  RESERVED_CLAIM_PREFIXES,
} from '@seamless-auth/types';
import { Request, Response } from 'express';

import { AuthEventService } from '../services/authEventService.js';
import {
  CustomClaimError,
  deleteCustomClaimSource,
  getCustomClaimSource,
  listCustomClaimSources,
  serializeCustomClaimSource,
  setCustomClaimSource,
} from '../services/customClaimService.js';
import { AuthenticatedRequest } from '../types/types.js';

function actorUserId(req: Request) {
  return (req as AuthenticatedRequest).user?.id ?? null;
}

function source(req: Request) {
  return {
    sourceKind: req.params.sourceKind as CustomClaimSourceKind,
    sourceName: req.params.sourceName as string,
  };
}

function sendError(res: Response, error: unknown) {
  if (error instanceof CustomClaimError) {
    return res.status(error.status).json({ error: error.message });
  }

  throw error;
}

export async function listCustomClaims(_req: Request, res: Response) {
  const sources = await listCustomClaimSources();
  return res.json({
    sources: sources.map(serializeCustomClaimSource),
    reservedNames: [...RESERVED_CLAIM_NAMES],
    reservedPrefixes: [...RESERVED_CLAIM_PREFIXES],
    budgetBytes: CUSTOM_CLAIMS_BUDGET_BYTES,
  });
}

export async function getCustomClaims(req: Request, res: Response) {
  const { sourceKind, sourceName } = source(req);
  try {
    return res.json({
      source: serializeCustomClaimSource(await getCustomClaimSource(sourceKind, sourceName)),
    });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function setCustomClaims(req: Request, res: Response) {
  const { sourceKind, sourceName } = source(req);
  try {
    const { source: saved, previous } = await setCustomClaimSource(
      sourceKind,
      sourceName,
      req.body.claims,
    );
    const names = Object.keys(saved.claims ?? {});

    // Names only: a value can be anything an administrator typed, and the audit log is permanent.
    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_custom_claims_updated',
      req,
      metadata: {
        sourceKind,
        sourceName,
        claimNames: names,
        added: names.filter((name) => !previous.includes(name)),
        removed: previous.filter((name) => !names.includes(name)),
      },
    });

    return res.json({ source: serializeCustomClaimSource(saved) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function deleteCustomClaims(req: Request, res: Response) {
  const { sourceKind, sourceName } = source(req);
  try {
    const removed = await deleteCustomClaimSource(sourceKind, sourceName);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_custom_claims_deleted',
      req,
      metadata: { sourceKind, sourceName, claimNames: Object.keys(removed.claims ?? {}) },
    });

    return res.json({ message: 'Custom claims deleted' });
  } catch (error) {
    return sendError(res, error);
  }
}
