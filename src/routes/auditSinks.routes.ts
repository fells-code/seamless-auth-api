/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import {
  createAuditSink,
  deleteAuditSink,
  getAuditSink,
  listAuditSinks,
  testAuditSink,
  updateAuditSink,
} from '../controllers/auditSinks.js';
import { createRouter } from '../lib/createRouter.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireStepUp } from '../middleware/requireStepUp.js';
import {
  AuditSinkIdParamSchema,
  AuditSinkListResponseSchema,
  AuditSinkResponseSchema,
  CalloutTestResponseSchema,
  CreateAuditSinkRequestSchema,
  UpdateAuditSinkRequestSchema,
} from '../schemas/auditSink.schemas.js';
import { ErrorSchema, MessageSchema } from '../schemas/generic.responses.js';
import { StepUpRequiredErrorSchema } from '../schemas/stepUp.responses.js';

/**
 * Streaming the audit log to a SIEM (ADR 0005, E7). Sending a test record is a write: it
 * connects to a destination an administrator chose, so it takes step-up like the rest.
 */
const router = createRouter('/admin');

const tags = ['Admin', 'Audit sinks'];
const read = { auth: 'access', tags, middleware: [requireAdmin('read')] };
const write = { auth: 'access', tags, middleware: [requireAdmin('write'), requireStepUp()] };

router.get(
  '/audit-sinks',
  {
    ...read,
    summary: 'List audit sinks',
    description: 'Each with its cursor and how many events it is behind the chain head.',
    schemas: { response: { 200: AuditSinkListResponseSchema } },
  },
  listAuditSinks,
);

router.post(
  '/audit-sinks',
  {
    ...write,
    summary: 'Create an audit sink',
    description:
      'Starts after the newest event unless `startAfterSeq` replays from an earlier one. Credentials are named as `_AUDIT_SINK_SECRET` env vars, never stored. A syslog sink is refused with a 400 until 0.23.1.',
    schemas: {
      body: CreateAuditSinkRequestSchema,
      response: { 201: AuditSinkResponseSchema, 400: ErrorSchema, 403: StepUpRequiredErrorSchema },
    },
  },
  createAuditSink,
);

router.get(
  '/audit-sinks/:id',
  {
    ...read,
    summary: 'Get an audit sink',
    schemas: {
      params: AuditSinkIdParamSchema,
      response: { 200: AuditSinkResponseSchema, 404: ErrorSchema },
    },
  },
  getAuditSink,
);

router.patch(
  '/audit-sinks/:id',
  {
    ...write,
    summary: 'Update an audit sink',
    description: 'The cursor is kept, so a sink turned back on resumes where it stopped.',
    schemas: {
      params: AuditSinkIdParamSchema,
      body: UpdateAuditSinkRequestSchema,
      response: {
        200: AuditSinkResponseSchema,
        400: ErrorSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  updateAuditSink,
);

router.delete(
  '/audit-sinks/:id',
  {
    ...write,
    summary: 'Delete an audit sink',
    schemas: {
      params: AuditSinkIdParamSchema,
      response: { 200: MessageSchema, 403: StepUpRequiredErrorSchema, 404: ErrorSchema },
    },
  },
  deleteAuditSink,
);

router.post(
  '/audit-sinks/:id/test',
  {
    ...write,
    summary: 'Send a test record',
    description:
      'Sends one record marked as a test, now. It is not part of the chain and does not move the cursor.',
    schemas: {
      params: AuditSinkIdParamSchema,
      response: {
        200: CalloutTestResponseSchema,
        403: StepUpRequiredErrorSchema,
        404: ErrorSchema,
      },
    },
  },
  testAuditSink,
);

export default router.router;
