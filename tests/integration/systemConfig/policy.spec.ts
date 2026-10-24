import request from 'supertest';
import { Application } from 'express';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { getSequelize } from '../../../src/models/index.js';
import { PolicyDraft } from '../../../src/models/policyDrafts.js';
import { PolicyVersion } from '../../../src/models/policyVersions.js';
import { Session } from '../../../src/models/sessions.js';
import { SystemConfig } from '../../../src/models/systemConfig.js';
import { User } from '../../../src/models/users.js';
import { PolicyDocumentSchema } from '../../../src/schemas/policy.schema.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { runPolicyDryRun } from '../../../src/services/policyDryRun.js';
import { buildSession } from '../../factories/sessionFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

vi.mock('../../../src/models/index.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/models/index.js')>()),
  getSequelize: vi.fn(),
}));

vi.mock('../../../src/services/policyDryRun.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/services/policyDryRun.js')>();

  return { ...actual, runPolicyDryRun: vi.fn(actual.runPolicyDryRun) };
});

let app: Application;

const applied = PolicyDocumentSchema.parse({
  login_methods: ['passkey', 'magic_link'],
  passkey_login_fallback_enabled: true,
});

const draftPolicy = PolicyDocumentSchema.parse({
  login_methods: ['passkey'],
  passkey_login_fallback_enabled: false,
});

const at = new Date('2026-10-20T00:00:00Z');
const query = vi.fn();

function version(number: number, extra = {}) {
  return {
    version: number,
    policy: applied,
    source: 'publish',
    createdBy: 'user-1',
    createdAt: at,
    rolledBackTo: null,
    ...extra,
  };
}

function draft(extra = {}) {
  return {
    id: 1,
    policy: draftPolicy,
    basedOnVersion: 3,
    updatedBy: 'user-1',
    updatedAt: at,
    destroy: vi.fn(),
    ...extra,
  };
}

function freshStepUp() {
  vi.mocked(Session.findOne).mockResolvedValue(
    buildSession({ stepUpVerifiedAt: new Date(), stepUpMethod: 'webauthn' }) as never,
  );
}

function loggedTypes() {
  return vi.mocked(AuthEventService.log).mock.calls.map(([options]) => options.type);
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  vi.mocked(getSystemConfig).mockResolvedValue(buildSystemConfig() as never);
  vi.mocked(SystemConfig.findAll).mockResolvedValue(
    Object.entries(applied).map(([key, value]) => ({ key, value })) as never,
  );
  vi.mocked(PolicyVersion.findOne).mockResolvedValue(version(3) as never);
  vi.mocked(PolicyVersion.create).mockImplementation((async (values: object) => ({
    createdAt: at,
    ...values,
  })) as never);
});

describe('GET /system-config/policy', () => {
  it('returns the published version and the draft', async () => {
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(draft() as never);

    const res = await request(app).get('/system-config/policy');

    expect(res.status).toBe(200);
    expect(res.body.published).toMatchObject({ version: 3, source: 'publish' });
    expect(res.body.draft).toMatchObject({ basedOnVersion: 3, policy: draftPolicy });
  });
});

describe('PUT /system-config/policy/draft', () => {
  it('saves the draft and audits it', async () => {
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(null);
    vi.mocked(PolicyDraft.create).mockImplementation((async (values: object) => ({
      updatedAt: at,
      ...values,
    })) as never);

    const res = await request(app)
      .put('/system-config/policy/draft')
      .send({ policy: { login_methods: ['passkey'], passkey_login_fallback_enabled: false } });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      policy: draftPolicy,
      basedOnVersion: 3,
      updatedAt: at.toISOString(),
      updatedBy: 'user-1',
    });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'policy_draft_saved', metadata: { basedOnVersion: 3 } }),
    );
    // A draft changes nothing until it is published.
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('rejects a policy that fails the schema', async () => {
    const res = await request(app)
      .put('/system-config/policy/draft')
      .send({ policy: { login_methods: [], passkey_login_fallback_enabled: true } });

    expect(res.status).toBe(400);
    expect(PolicyDraft.create).not.toHaveBeenCalled();
  });
});

describe('DELETE /system-config/policy/draft', () => {
  it('discards the draft', async () => {
    vi.mocked(PolicyDraft.destroy).mockResolvedValue(1);

    const res = await request(app).delete('/system-config/policy/draft');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'Policy draft discarded' });
    expect(loggedTypes()).toContain('policy_draft_discarded');
  });

  it('answers 404 when there is no draft', async () => {
    const res = await request(app).delete('/system-config/policy/draft');

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('policy_draft_not_found');
    expect(loggedTypes()).not.toContain('policy_draft_discarded');
  });
});

describe('POST /system-config/policy/publish', () => {
  it('requires a fresh step-up', async () => {
    vi.mocked(Session.findOne).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: null, stepUpMethod: null }) as never,
    );

    const res = await request(app)
      .post('/system-config/policy/publish')
      .send({ expectedVersion: 3 });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('step_up_required');
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('publishes the draft as the next version', async () => {
    freshStepUp();
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(draft() as never);

    const res = await request(app)
      .post('/system-config/policy/publish')
      .send({ expectedVersion: 3 });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      version: 4,
      policy: draftPolicy,
      source: 'publish',
      publishedAt: at.toISOString(),
      publishedBy: 'user-1',
    });
    expect(SystemConfig.upsert).toHaveBeenCalledWith(
      { key: 'login_methods', value: ['passkey'], updatedBy: 'user-1' },
      expect.anything(),
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'policy_published',
        metadata: { version: 4, previousVersion: 3, basedOnVersion: 3 },
      }),
    );
  });

  it('answers 409 when another version was published since', async () => {
    freshStepUp();
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(version(5) as never);

    const res = await request(app)
      .post('/system-config/policy/publish')
      .send({ expectedVersion: 3 });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('policy_version_conflict');
    expect(res.body.message).toContain('Version 5');
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('answers 404 when there is no draft to publish', async () => {
    freshStepUp();
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(null);

    const res = await request(app)
      .post('/system-config/policy/publish')
      .send({ expectedVersion: 3 });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('policy_draft_not_found');
  });

  it('requires expectedVersion', async () => {
    freshStepUp();

    const res = await request(app).post('/system-config/policy/publish').send({});

    expect(res.status).toBe(400);
  });

  it('passes an unexpected failure to the error handler', async () => {
    freshStepUp();
    vi.mocked(PolicyDraft.findByPk).mockRejectedValue(new Error('db down'));

    const res = await request(app)
      .post('/system-config/policy/publish')
      .send({ expectedVersion: 3 });

    expect(res.status).toBe(500);
  });
});

describe('POST /system-config/policy/rollback', () => {
  it('requires a fresh step-up', async () => {
    vi.mocked(Session.findOne).mockResolvedValue(
      buildSession({ stepUpVerifiedAt: null, stepUpMethod: null }) as never,
    );

    const res = await request(app)
      .post('/system-config/policy/rollback')
      .send({ version: 1, expectedVersion: 3 });

    expect(res.status).toBe(403);
  });

  it('publishes a copy of the older version', async () => {
    freshStepUp();
    vi.mocked(PolicyVersion.findByPk).mockResolvedValue(
      version(1, { source: 'bootstrap' }) as never,
    );

    const res = await request(app)
      .post('/system-config/policy/rollback')
      .send({ version: 1, expectedVersion: 3 });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ version: 4, source: 'rollback', rolledBackTo: 1 });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'policy_rolled_back',
        metadata: { version: 4, rolledBackTo: 1, previousVersion: 3 },
      }),
    );
  });

  it('answers 409 when the expected version is stale', async () => {
    freshStepUp();

    const res = await request(app)
      .post('/system-config/policy/rollback')
      .send({ version: 1, expectedVersion: 2 });

    expect(res.status).toBe(409);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('answers 404 for a version that does not exist', async () => {
    freshStepUp();
    vi.mocked(PolicyVersion.findByPk).mockResolvedValue(null);

    const res = await request(app)
      .post('/system-config/policy/rollback')
      .send({ version: 9, expectedVersion: 3 });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('policy_version_not_found');
  });
});

describe('GET /system-config/policy/versions', () => {
  it('lists versions newest first', async () => {
    vi.mocked(PolicyVersion.findAll).mockResolvedValue([
      version(2, { source: 'config_patch' }),
      version(1, { source: 'bootstrap', createdBy: null }),
    ] as never);

    const res = await request(app).get('/system-config/policy/versions');

    expect(res.status).toBe(200);
    expect(res.body.versions.map((entry: { version: number }) => entry.version)).toEqual([2, 1]);
    expect(res.body.versions[1].publishedBy).toBeNull();
  });
});

describe('POST /system-config/policy/dry-run', () => {
  it('evaluates the policy in the request', async () => {
    query.mockResolvedValueOnce([
      {
        userId: 'u-1',
        email: 'a@example.com',
        phone: null,
        method: 'magic_link',
        signIns: 2,
        hasPasskey: false,
        oauthProviders: [],
      },
    ]);

    const res = await request(app)
      .post('/system-config/policy/dry-run')
      .send({
        policy: { login_methods: ['passkey'], passkey_login_fallback_enabled: true },
        days: 3,
      });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      signInsEvaluated: 2,
      usersEvaluated: 1,
      usersLockedOut: 1,
      breakGlassAccounts: 0,
      wouldFail: [{ userId: 'u-1', signIns: 2, reasons: ['method_disabled'], lockedOut: true }],
    });
    expect(res.body).not.toHaveProperty('capped');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'policy_dry_run',
        metadata: expect.objectContaining({ candidate: 'request', days: 3, wouldFail: 1 }),
      }),
    );
  });

  it('evaluates the draft when no policy is sent', async () => {
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(draft() as never);
    query.mockResolvedValueOnce([]);

    const res = await request(app).post('/system-config/policy/dry-run').send({});

    expect(res.status).toBe(200);
    expect(res.body.wouldFail).toEqual([]);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: expect.objectContaining({ candidate: 'draft', days: 7 }),
      }),
    );
  });

  it('records that a run stopped at the account cap', async () => {
    vi.mocked(runPolicyDryRun).mockResolvedValueOnce({
      window: { from: at.toISOString(), to: at.toISOString() },
      signInsEvaluated: 0,
      usersEvaluated: 0,
      wouldFail: [],
      usersLockedOut: 0,
      breakGlassAccounts: 0,
      capped: true,
    });

    const res = await request(app)
      .post('/system-config/policy/dry-run')
      .send({ policy: { login_methods: ['passkey'], passkey_login_fallback_enabled: true } });

    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('capped');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ metadata: expect.objectContaining({ capped: true }) }),
    );
  });

  it('answers 400 when there is neither a policy nor a draft', async () => {
    vi.mocked(PolicyDraft.findByPk).mockResolvedValue(null);

    const res = await request(app).post('/system-config/policy/dry-run').send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('policy_candidate_required');
    expect(query).not.toHaveBeenCalled();
  });

  it('refuses a window longer than 30 days', async () => {
    const res = await request(app).post('/system-config/policy/dry-run').send({ days: 31 });

    expect(res.status).toBe(400);
  });
});

describe('PATCH /system-config/admin policy versioning', () => {
  beforeEach(() => {
    vi.mocked(User.findAll).mockResolvedValue([] as never);
    freshStepUp();
  });

  it('records a config_patch version in the same transaction', async () => {
    vi.mocked(PolicyVersion.findOne).mockResolvedValue(
      version(3, { policy: draftPolicy }) as never,
    );

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ login_methods: ['passkey', 'magic_link'] });

    expect(res.status).toBe(200);
    expect(PolicyVersion.create).toHaveBeenCalledWith(
      expect.objectContaining({ version: 4, source: 'config_patch', createdBy: 'user-1' }),
      expect.anything(),
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'system_config_updated',
        metadata: expect.objectContaining({ policyVersion: 4 }),
      }),
    );
  });

  it('records no version when the patch leaves the policy as it was', async () => {
    const res = await request(app)
      .patch('/system-config/admin')
      .send({ login_methods: ['passkey', 'magic_link'] });

    expect(res.status).toBe(200);
    expect(PolicyVersion.create).not.toHaveBeenCalled();
    expect(vi.mocked(AuthEventService.log).mock.calls[0][0].metadata).not.toHaveProperty(
      'policyVersion',
    );
  });

  it('leaves versioning alone for a patch that names no policy key', async () => {
    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
    expect(PolicyVersion.sequelize!.query).not.toHaveBeenCalled();
    expect(PolicyVersion.create).not.toHaveBeenCalled();
  });
});
