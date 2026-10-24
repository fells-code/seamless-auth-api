import { beforeEach, describe, expect, it, vi } from 'vitest';

import { invalidateSystemConfigCache } from '../../../src/config/getSystemConfig.js';
import { PolicyDraft } from '../../../src/models/policyDrafts.js';
import { PolicyVersion } from '../../../src/models/policyVersions.js';
import { SystemConfig } from '../../../src/models/systemConfig.js';
import { POLICY_KEYS, PolicyDocumentSchema } from '../../../src/schemas/policy.schema.js';
import {
  discardPolicyDraft,
  getPolicyState,
  isPolicyKey,
  listPolicyVersions,
  lockPolicyForConfigPatch,
  PolicyDraftNotFoundError,
  PolicyVersionConflictError,
  PolicyVersionNotFoundError,
  publishPolicyDraft,
  recordBootstrapPolicyVersion,
  recordConfigPatchPolicyVersion,
  rollbackPolicy,
  savePolicyDraft,
} from '../../../src/services/policyVersionService.js';

const applied = PolicyDocumentSchema.parse({
  login_methods: ['passkey', 'magic_link'],
  passkey_login_fallback_enabled: true,
});

const stricter = PolicyDocumentSchema.parse({
  login_methods: ['passkey'],
  passkey_login_fallback_enabled: false,
});

const publishedAt = new Date('2026-10-01T00:00:00Z');

function versionRow(version: number, policy: unknown = applied, extra = {}) {
  return {
    version,
    policy,
    source: 'publish',
    createdBy: 'admin-1',
    createdAt: publishedAt,
    rolledBackTo: null,
    ...extra,
  };
}

function draftRow(extra = {}) {
  return {
    id: 1,
    policy: stricter,
    basedOnVersion: 3,
    updatedBy: 'admin-1',
    updatedAt: publishedAt,
    update: vi.fn(async function (this: object, values: object) {
      return { ...this, ...values };
    }),
    destroy: vi.fn(),
    ...extra,
  };
}

const tx = { LOCK: { UPDATE: 'UPDATE' } };

beforeEach(() => {
  vi.mocked(SystemConfig.sequelize!.transaction).mockImplementation(((fn: any) => fn(tx)) as never);
  vi.mocked(SystemConfig.findAll).mockResolvedValue(
    Object.entries(applied).map(([key, value]) => ({ key, value })) as never,
  );
  vi.mocked(PolicyVersion.create).mockImplementation((async (values: object) => ({
    createdAt: publishedAt,
    ...values,
  })) as never);
});

function lockTaken() {
  expect(PolicyVersion.sequelize!.query).toHaveBeenCalledWith(
    'SELECT pg_advisory_xact_lock(:key)',
    expect.objectContaining({ transaction: tx }),
  );
}

describe('isPolicyKey', () => {
  it('names the keys a change can lock people out with', () => {
    expect(isPolicyKey('login_methods')).toBe(true);
    expect(isPolicyKey('account_recovery')).toBe(true);
    expect(isPolicyKey('app_name')).toBe(false);
  });
});

describe('recordBootstrapPolicyVersion', () => {
  it('records the applied policy as version 1 on the first boot', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(null);

    const created = await recordBootstrapPolicyVersion();

    lockTaken();
    expect(PolicyVersion.create).toHaveBeenCalledWith(
      expect.objectContaining({
        version: 1,
        source: 'bootstrap',
        createdBy: null,
        policy: applied,
      }),
      { transaction: tx },
    );
    expect(created?.version).toBe(1);
  });

  it('records nothing when the latest version is the policy in force', async () => {
    // Stored JSONB comes back in its own key order, which must not read as a change.
    const reordered = Object.fromEntries(Object.entries(applied).reverse());
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(4, reordered) as never);

    expect(await recordBootstrapPolicyVersion()).toBeNull();
    expect(PolicyVersion.create).not.toHaveBeenCalled();
  });

  it('records a new version when env changed the policy since the last one', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(4, stricter) as never);

    await recordBootstrapPolicyVersion();

    expect(PolicyVersion.create).toHaveBeenCalledWith(
      expect.objectContaining({ version: 5, source: 'bootstrap' }),
      { transaction: tx },
    );
  });
});

describe('config patch versioning', () => {
  it('records the replaced policy first when there is no version yet', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValueOnce(null).mockResolvedValueOnce(null);

    await lockPolicyForConfigPatch(tx as never);

    lockTaken();
    expect(PolicyVersion.create).toHaveBeenCalledWith(
      expect.objectContaining({ version: 1, source: 'bootstrap' }),
      { transaction: tx },
    );
  });

  it('records the patched policy as a config_patch version', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(2, stricter) as never);

    const created = await recordConfigPatchPolicyVersion(tx as never, 'admin-2');

    expect(PolicyVersion.create).toHaveBeenCalledWith(
      expect.objectContaining({ version: 3, source: 'config_patch', createdBy: 'admin-2' }),
      { transaction: tx },
    );
    expect(created?.version).toBe(3);
  });
});

describe('getPolicyState', () => {
  it('returns the published version and the draft', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(3) as never);
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(draftRow() as never);

    const state = await getPolicyState();

    expect(state.published).toEqual({
      version: 3,
      policy: applied,
      source: 'publish',
      publishedAt: publishedAt.toISOString(),
      publishedBy: 'admin-1',
    });
    expect(state.draft).toEqual({
      policy: stricter,
      basedOnVersion: 3,
      updatedAt: publishedAt.toISOString(),
      updatedBy: 'admin-1',
    });
    expect(PolicyVersion.sequelize!.query).not.toHaveBeenCalled();
  });

  it('records the baseline when no version exists yet', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(null);
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(null);

    const state = await getPolicyState();

    lockTaken();
    expect(state.published.version).toBe(1);
    expect(state.published.source).toBe('bootstrap');
    expect(state.published.publishedBy).toBeNull();
    expect(state.draft).toBeNull();
  });
});

describe('listPolicyVersions', () => {
  it('lists newest first and carries the version a rollback restored', async () => {
    vi.mocked(PolicyVersion.findAll).mockResolvedValue([
      versionRow(2, applied, { source: 'rollback', rolledBackTo: 1, createdBy: null }),
      versionRow(1),
    ] as never);

    const versions = await listPolicyVersions();

    expect(PolicyVersion.findAll).toHaveBeenCalledWith({ order: [['version', 'DESC']] });
    expect(versions[0]).toMatchObject({ version: 2, rolledBackTo: 1, publishedBy: null });
    expect(versions[1]).not.toHaveProperty('rolledBackTo');
  });
});

describe('savePolicyDraft', () => {
  it('starts a draft from the published version', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(3) as never);
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(null);
    vi.mocked(PolicyDraft.create).mockImplementation((async (values: object) => values) as never);

    await savePolicyDraft(stricter, 'admin-1');

    lockTaken();
    expect(PolicyDraft.create).toHaveBeenCalledWith(
      {
        id: 1,
        policy: stricter,
        basedOnVersion: 3,
        createdBy: 'admin-1',
        updatedBy: 'admin-1',
      },
      { transaction: tx },
    );
  });

  it('keeps the version an existing draft was started from', async () => {
    const existing = draftRow({ basedOnVersion: 2 });
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(5) as never);
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(existing as never);

    const saved = await savePolicyDraft(applied, 'admin-2');

    expect(existing.update).toHaveBeenCalledWith(
      { policy: applied, updatedBy: 'admin-2' },
      { transaction: tx },
    );
    expect(saved.basedOnVersion).toBe(2);
    expect(PolicyDraft.create).not.toHaveBeenCalled();
  });
});

describe('discardPolicyDraft', () => {
  it('reports whether there was a draft', async () => {
    vi.mocked(PolicyDraft.destroy).mockResolvedValueOnce(1).mockResolvedValueOnce(0);

    expect(await discardPolicyDraft()).toBe(true);
    expect(await discardPolicyDraft()).toBe(false);
    expect(PolicyDraft.destroy).toHaveBeenCalledWith({ where: { id: 1 } });
  });
});

describe('publishPolicyDraft', () => {
  it('applies every policy key, records the version and clears the draft', async () => {
    const draft = draftRow();
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(3) as never);
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(draft as never);

    const result = await publishPolicyDraft({ expectedVersion: 3, actor: 'admin-1' });

    lockTaken();
    for (const key of POLICY_KEYS) {
      expect(SystemConfig.upsert).toHaveBeenCalledWith(
        { key, value: stricter[key], updatedBy: 'admin-1' },
        { transaction: tx },
      );
    }
    expect(PolicyVersion.create).toHaveBeenCalledWith(
      expect.objectContaining({ version: 4, source: 'publish', policy: stricter }),
      { transaction: tx },
    );
    expect(draft.destroy).toHaveBeenCalledWith({ transaction: tx });
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
    expect(result).toMatchObject({ previousVersion: 3, basedOnVersion: 3 });
    expect(result.published.version).toBe(4);
  });

  it('refuses a stale expected version before writing anything', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(4) as never);

    const publishing = publishPolicyDraft({ expectedVersion: 3, actor: 'admin-1' });

    await expect(publishing).rejects.toBeInstanceOf(PolicyVersionConflictError);
    await expect(publishing).rejects.toMatchObject({ currentVersion: 4 });
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
    expect(PolicyVersion.create).not.toHaveBeenCalled();
    expect(invalidateSystemConfigCache).not.toHaveBeenCalled();
  });

  it('refuses when there is no draft', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(3) as never);
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(null);

    await expect(publishPolicyDraft({ expectedVersion: 3, actor: null })).rejects.toBeInstanceOf(
      PolicyDraftNotFoundError,
    );
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });
});

describe('rollbackPolicy', () => {
  it('publishes a copy of the older version as the next one', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(5, stricter) as never);
    vi.mocked(PolicyVersion.findByPk).mockResolvedValue(versionRow(2, applied) as never);

    const result = await rollbackPolicy({ version: 2, expectedVersion: 5, actor: 'admin-1' });

    lockTaken();
    expect(SystemConfig.upsert).toHaveBeenCalledWith(
      { key: 'login_methods', value: applied.login_methods, updatedBy: 'admin-1' },
      { transaction: tx },
    );
    expect(PolicyVersion.create).toHaveBeenCalledWith(
      expect.objectContaining({ version: 6, source: 'rollback', rolledBackTo: 2 }),
      { transaction: tx },
    );
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
    expect(result.previousVersion).toBe(5);
  });

  it('refuses a stale expected version', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(6) as never);

    await expect(
      rollbackPolicy({ version: 2, expectedVersion: 5, actor: null }),
    ).rejects.toBeInstanceOf(PolicyVersionConflictError);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('refuses a version that does not exist', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(versionRow(5) as never);
    vi.mocked(PolicyVersion.findByPk).mockResolvedValue(null);

    await expect(
      rollbackPolicy({ version: 9, expectedVersion: 5, actor: null }),
    ).rejects.toBeInstanceOf(PolicyVersionNotFoundError);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });
});
