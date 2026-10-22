/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Transaction } from 'sequelize';

import { invalidateSystemConfigCache } from '../config/getSystemConfig.js';
import { POLICY_DRAFT_ID, PolicyDraft } from '../models/policyDrafts.js';
import { PolicyVersion } from '../models/policyVersions.js';
import { SystemConfig } from '../models/systemConfig.js';
import {
  POLICY_KEYS,
  type PolicyDocument,
  PolicyDocumentSchema,
  type PolicyDraft as PolicyDraftView,
  type PolicyStateResponse,
  type PolicyVersion as PolicyVersionView,
  type PolicyVersionSource,
} from '../schemas/policy.schema.js';

// Every write that assigns a version number takes this lock first, so two publishers
// cannot both read version N and both write N + 1.
const POLICY_VERSION_LOCK_KEY = 4020403;

export class PolicyVersionConflictError extends Error {
  constructor(readonly currentVersion: number) {
    super(`Policy version ${currentVersion} has been published since`);
    this.name = 'PolicyVersionConflictError';
  }
}

export class PolicyDraftNotFoundError extends Error {
  constructor() {
    super('There is no policy draft');
    this.name = 'PolicyDraftNotFoundError';
  }
}

export class PolicyVersionNotFoundError extends Error {
  constructor(readonly version: number) {
    super(`Policy version ${version} does not exist`);
    this.name = 'PolicyVersionNotFoundError';
  }
}

export function isPolicyKey(key: string): boolean {
  return (POLICY_KEYS as readonly string[]).includes(key);
}

// Parsing fixes the key order, so two documents compare equal however they were stored.
function samePolicy(a: unknown, b: unknown) {
  return (
    JSON.stringify(PolicyDocumentSchema.parse(a)) === JSON.stringify(PolicyDocumentSchema.parse(b))
  );
}

function transaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
  return SystemConfig.sequelize!.transaction(work);
}

async function lockPolicyVersions(tx: Transaction) {
  await PolicyVersion.sequelize!.query('SELECT pg_advisory_xact_lock(:key)', {
    replacements: { key: POLICY_VERSION_LOCK_KEY },
    transaction: tx,
  });
}

async function readAppliedPolicy(tx: Transaction): Promise<PolicyDocument> {
  const rows = await SystemConfig.findAll({
    where: { key: [...POLICY_KEYS] },
    transaction: tx,
  });

  return PolicyDocumentSchema.parse(Object.fromEntries(rows.map((row) => [row.key, row.value])));
}

async function applyPolicy(tx: Transaction, policy: PolicyDocument, updatedBy: string | null) {
  for (const key of POLICY_KEYS) {
    // updatedBy marks the row admin-managed, so the next boot does not put the env value back.
    await SystemConfig.upsert({ key, value: policy[key], updatedBy }, { transaction: tx });
  }
}

function latestVersion(tx?: Transaction) {
  return PolicyVersion.findOne({ order: [['version', 'DESC']], transaction: tx });
}

async function appendVersion(
  tx: Transaction,
  entry: {
    policy: PolicyDocument;
    source: PolicyVersionSource;
    createdBy: string | null;
    rolledBackTo?: number;
  },
) {
  const latest = await latestVersion(tx);

  return PolicyVersion.create(
    {
      version: (latest?.version ?? 0) + 1,
      policy: entry.policy,
      source: entry.source,
      createdBy: entry.createdBy,
      rolledBackTo: entry.rolledBackTo ?? null,
    },
    { transaction: tx },
  );
}

/**
 * Records the applied policy as a new version when it differs from the latest one, or
 * when there is no version yet. Callers hold the version lock.
 */
async function recordIfChanged(
  tx: Transaction,
  source: PolicyVersionSource,
  createdBy: string | null,
) {
  const applied = await readAppliedPolicy(tx);
  const latest = await latestVersion(tx);

  if (latest && samePolicy(latest.policy, applied)) {
    return null;
  }

  return appendVersion(tx, { policy: applied, source, createdBy });
}

async function currentVersion(tx: Transaction) {
  return (await latestVersion(tx)) ?? (await recordIfChanged(tx, 'bootstrap', null))!;
}

export function serializePolicyVersion(row: PolicyVersion): PolicyVersionView {
  return {
    version: row.version,
    policy: PolicyDocumentSchema.parse(row.policy),
    source: row.source,
    publishedAt: row.createdAt.toISOString(),
    publishedBy: row.createdBy ?? null,
    ...(row.rolledBackTo ? { rolledBackTo: row.rolledBackTo } : {}),
  };
}

export function serializePolicyDraft(row: PolicyDraft): PolicyDraftView {
  return {
    policy: PolicyDocumentSchema.parse(row.policy),
    basedOnVersion: row.basedOnVersion,
    updatedAt: row.updatedAt.toISOString(),
    updatedBy: row.updatedBy ?? null,
  };
}

/**
 * Run at startup, after `bootstrapSystemConfig`. The first boot after upgrading records
 * the policy in force as version 1, and a later boot records a new version only when env
 * changed a policy key that no administrator has taken over.
 */
export function recordBootstrapPolicyVersion() {
  return transaction(async (tx) => {
    await lockPolicyVersions(tx);
    return recordIfChanged(tx, 'bootstrap', null);
  });
}

/**
 * For a whole-config PATCH that names a policy key, inside its transaction. Call it
 * before the patch is written, so an instance that has no version yet records the policy
 * the patch replaces rather than losing it.
 */
export async function lockPolicyForConfigPatch(tx: Transaction) {
  await lockPolicyVersions(tx);
  await currentVersion(tx);
}

/** After the patch is written, in the same transaction. Null when the policy is unchanged. */
export function recordConfigPatchPolicyVersion(tx: Transaction, createdBy: string | null) {
  return recordIfChanged(tx, 'config_patch', createdBy);
}

export async function getPolicyState(): Promise<PolicyStateResponse> {
  const published = await transaction(async (tx) => {
    const latest = await latestVersion(tx);

    if (latest) return latest;

    await lockPolicyVersions(tx);
    return currentVersion(tx);
  });
  const draft = await PolicyDraft.findByPk(POLICY_DRAFT_ID);

  return {
    published: serializePolicyVersion(published),
    draft: draft ? serializePolicyDraft(draft) : null,
  };
}

export async function getPolicyDraft() {
  return PolicyDraft.findByPk(POLICY_DRAFT_ID);
}

export async function listPolicyVersions() {
  const rows = await PolicyVersion.findAll({ order: [['version', 'DESC']] });

  return rows.map(serializePolicyVersion);
}

/**
 * Replaces the draft. A draft keeps the version it was started from across saves, so a
 * draft begun before someone else published still reads as based on the older version.
 */
export function savePolicyDraft(policy: PolicyDocument, actor: string | null) {
  return transaction(async (tx) => {
    await lockPolicyVersions(tx);
    const published = await currentVersion(tx);
    const existing = await PolicyDraft.findByPk(POLICY_DRAFT_ID, { transaction: tx });

    if (existing) {
      return existing.update({ policy, updatedBy: actor }, { transaction: tx });
    }

    return PolicyDraft.create(
      {
        id: POLICY_DRAFT_ID,
        policy,
        basedOnVersion: published.version,
        createdBy: actor,
        updatedBy: actor,
      },
      { transaction: tx },
    );
  });
}

/** Whether there was a draft to discard. */
export async function discardPolicyDraft() {
  return (await PolicyDraft.destroy({ where: { id: POLICY_DRAFT_ID } })) > 0;
}

/**
 * Applies the draft to `system_config` and records it as the next version, in one
 * transaction, so a publish that fails part way leaves the previous policy in force.
 */
export async function publishPolicyDraft(params: {
  expectedVersion: number;
  actor: string | null;
}) {
  const result = await transaction(async (tx) => {
    await lockPolicyVersions(tx);
    const previous = await currentVersion(tx);

    if (previous.version !== params.expectedVersion) {
      throw new PolicyVersionConflictError(previous.version);
    }

    const draft = await PolicyDraft.findByPk(POLICY_DRAFT_ID, { transaction: tx });

    if (!draft) {
      throw new PolicyDraftNotFoundError();
    }

    const policy = PolicyDocumentSchema.parse(draft.policy);

    await applyPolicy(tx, policy, params.actor);
    const published = await appendVersion(tx, {
      policy,
      source: 'publish',
      createdBy: params.actor,
    });
    await draft.destroy({ transaction: tx });

    return { published, previousVersion: previous.version, basedOnVersion: draft.basedOnVersion };
  });

  invalidateSystemConfigCache();

  return result;
}

/** Publishes a copy of an older version as the next one. History is never rewritten. */
export async function rollbackPolicy(params: {
  version: number;
  expectedVersion: number;
  actor: string | null;
}) {
  const result = await transaction(async (tx) => {
    await lockPolicyVersions(tx);
    const previous = await currentVersion(tx);

    if (previous.version !== params.expectedVersion) {
      throw new PolicyVersionConflictError(previous.version);
    }

    const target = await PolicyVersion.findByPk(params.version, { transaction: tx });

    if (!target) {
      throw new PolicyVersionNotFoundError(params.version);
    }

    const policy = PolicyDocumentSchema.parse(target.policy);

    await applyPolicy(tx, policy, params.actor);
    const published = await appendVersion(tx, {
      policy,
      source: 'rollback',
      createdBy: params.actor,
      rolledBackTo: target.version,
    });

    return { published, previousVersion: previous.version };
  });

  invalidateSystemConfigCache();

  return result;
}
