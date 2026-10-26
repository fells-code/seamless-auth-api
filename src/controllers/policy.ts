/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { resolveSystemConfigUpdatedBy } from '../lib/systemConfigActor.js';
import { type PolicyDocument, PolicyDocumentSchema } from '../schemas/policy.schema.js';
import { AuthEventService } from '../services/authEventService.js';
import { runPolicyDryRun } from '../services/policyDryRun.js';
import {
  discardPolicyDraft,
  getPolicyDraft,
  getPolicyState,
  listPolicyVersions,
  PolicyDraftNotFoundError,
  PolicyVersionConflictError,
  PolicyVersionNotFoundError,
  publishPolicyDraft,
  rollbackPolicy,
  savePolicyDraft,
  serializePolicyDraft,
  serializePolicyVersion,
} from '../services/policyVersionService.js';
import { ServiceRequest } from '../types/types.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('policy');

function refuse(res: Response, error: unknown) {
  if (error instanceof PolicyVersionConflictError) {
    return res.status(409).json({
      error: 'policy_version_conflict',
      message: `Version ${error.currentVersion} is the published policy now. Review it and retry.`,
    });
  }

  if (error instanceof PolicyDraftNotFoundError) {
    return res.status(404).json({ error: 'policy_draft_not_found' });
  }

  if (error instanceof PolicyVersionNotFoundError) {
    return res.status(404).json({ error: 'policy_version_not_found' });
  }

  throw error;
}

export async function getPolicyStateHandler(_req: Request, res: Response) {
  return res.status(200).json(await getPolicyState());
}

export async function listPolicyVersionsHandler(_req: Request, res: Response) {
  return res.status(200).json({ versions: await listPolicyVersions() });
}

export async function savePolicyDraftHandler(req: ServiceRequest, res: Response) {
  const { policy } = req.body as { policy: PolicyDocument };
  const draft = await savePolicyDraft(policy, resolveSystemConfigUpdatedBy(req));

  await AuthEventService.log({
    type: 'policy_draft_saved',
    req,
    metadata: { basedOnVersion: draft.basedOnVersion },
  });

  return res.status(200).json(serializePolicyDraft(draft));
}

export async function discardPolicyDraftHandler(req: ServiceRequest, res: Response) {
  if (!(await discardPolicyDraft())) {
    return res.status(404).json({ error: 'policy_draft_not_found' });
  }

  await AuthEventService.log({ type: 'policy_draft_discarded', req });

  return res.status(200).json({ message: 'Policy draft discarded' });
}

export async function publishPolicyHandler(req: ServiceRequest, res: Response) {
  const { expectedVersion } = req.body as { expectedVersion: number };
  let result: Awaited<ReturnType<typeof publishPolicyDraft>>;

  try {
    result = await publishPolicyDraft({
      expectedVersion,
      actor: resolveSystemConfigUpdatedBy(req),
    });
  } catch (error) {
    return refuse(res, error);
  }

  const published = serializePolicyVersion(result.published);

  await AuthEventService.log({
    type: 'policy_published',
    req,
    metadata: {
      version: published.version,
      previousVersion: result.previousVersion,
      basedOnVersion: result.basedOnVersion,
    },
  });

  return res.status(200).json(published);
}

export async function rollbackPolicyHandler(req: ServiceRequest, res: Response) {
  const { version, expectedVersion } = req.body as { version: number; expectedVersion: number };
  let result: Awaited<ReturnType<typeof rollbackPolicy>>;

  try {
    result = await rollbackPolicy({
      version,
      expectedVersion,
      actor: resolveSystemConfigUpdatedBy(req),
    });
  } catch (error) {
    return refuse(res, error);
  }

  const published = serializePolicyVersion(result.published);

  await AuthEventService.log({
    type: 'policy_rolled_back',
    req,
    metadata: {
      version: published.version,
      rolledBackTo: version,
      previousVersion: result.previousVersion,
    },
  });

  return res.status(200).json(published);
}

export async function dryRunPolicyHandler(req: ServiceRequest, res: Response) {
  const { policy, days } = req.body as { policy?: PolicyDocument; days: number };
  const draft = policy ? null : await getPolicyDraft();
  const candidate = policy ?? (draft ? PolicyDocumentSchema.parse(draft.policy) : null);

  if (!candidate) {
    return res.status(400).json({
      error: 'policy_candidate_required',
      message: 'Send a policy to evaluate, or save a draft first.',
    });
  }

  const report = await runPolicyDryRun({ policy: candidate, days });
  const { capped } = report;

  if (capped) {
    logger.warn(`Policy dry run evaluated only the first ${report.usersEvaluated} accounts`);
  }

  await AuthEventService.log({
    type: 'policy_dry_run',
    req,
    metadata: {
      candidate: policy ? 'request' : 'draft',
      days,
      signInsEvaluated: report.signInsEvaluated,
      usersEvaluated: report.usersEvaluated,
      wouldFail: report.wouldFail.length,
      usersLockedOut: report.usersLockedOut,
      capped,
    },
  });

  return res.status(200).json(report);
}
