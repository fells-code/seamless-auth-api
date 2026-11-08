/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { AuditSinkSettings } from '@seamless-auth/types';
import { Request, Response } from 'express';

import {
  AuditSinkError,
  chainHead,
  createSink,
  deleteSink,
  getSink,
  listSinks,
  sendSinkTest,
  serializeSink,
  updateSink,
} from '../services/auditSinkService.js';
import { AuthEventService } from '../services/authEventService.js';
import { AuthenticatedRequest, RouteRequest } from '../types/types.js';

function actorUserId(req: Request) {
  return (req as AuthenticatedRequest).user?.id ?? null;
}

/** Where a sink sends, for the audit log. A URL is recorded without its query string. */
function destination(settings: AuditSinkSettings) {
  if (settings.kind === 'otlp') {
    const url = new URL(settings.endpoint);
    return `${url.origin}${url.pathname}`;
  }
  return `${settings.transport}://${settings.host}:${settings.port}`;
}

function sendError(res: Response, error: unknown) {
  if (error instanceof AuditSinkError) {
    return res.status(error.status).json({ error: error.message });
  }

  throw error;
}

export async function listAuditSinks(_req: Request, res: Response) {
  const [sinks, head] = await Promise.all([listSinks(), chainHead()]);
  return res.json({ sinks: sinks.map((sink) => serializeSink(sink, head)) });
}

export async function getAuditSink(req: RouteRequest, res: Response) {
  try {
    const sink = await getSink(req.params.id);
    return res.json({ sink: serializeSink(sink, await chainHead()) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function createAuditSink(req: Request, res: Response) {
  try {
    const sink = await createSink(req.body, actorUserId(req));

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_audit_sink_created',
      req,
      metadata: {
        sinkId: sink.id,
        kind: sink.kind,
        destination: destination(sink.settings),
        enabled: sink.enabled,
        cursorSeq: Number(sink.cursorSeq),
      },
    });

    return res.status(201).json({ sink: serializeSink(sink, await chainHead()) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function updateAuditSink(req: RouteRequest, res: Response) {
  try {
    const sink = await updateSink(req.params.id, req.body);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_audit_sink_updated',
      req,
      metadata: {
        sinkId: sink.id,
        changed: Object.keys(req.body),
        destination: destination(sink.settings),
        enabled: sink.enabled,
      },
    });

    return res.json({ sink: serializeSink(sink, await chainHead()) });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function deleteAuditSink(req: RouteRequest, res: Response) {
  try {
    const sink = await deleteSink(req.params.id);

    await AuthEventService.log({
      actorUserId: actorUserId(req),
      type: 'admin_audit_sink_deleted',
      req,
      metadata: {
        sinkId: sink.id,
        kind: sink.kind,
        destination: destination(sink.settings),
        cursorSeq: Number(sink.cursorSeq),
      },
    });

    return res.json({ message: 'Audit sink deleted' });
  } catch (error) {
    return sendError(res, error);
  }
}

export async function testAuditSink(req: RouteRequest, res: Response) {
  try {
    return res.json(await sendSinkTest(req.params.id));
  } catch (error) {
    return sendError(res, error);
  }
}
