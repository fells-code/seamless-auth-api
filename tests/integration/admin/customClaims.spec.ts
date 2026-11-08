import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/models/oidcClients.js')>();
  actual.OidcClient.findByPk = vi.fn() as never;
  return actual;
});

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { CustomClaim } from '../../../src/models/customClaims.js';
import { OidcClient } from '../../../src/models/oidcClients.js';
import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory';
import { buildSystemConfig } from '../../factories/systemConfigFactory';

let app: Application;
const now = new Date('2026-11-07T12:00:00.000Z');

function buildSource(overrides: Record<string, unknown> = {}) {
  const record: any = {
    sourceKind: 'instance_role',
    sourceName: 'user',
    claims: { plan: 'pro' },
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  record.update = vi.fn(async (values: Record<string, unknown>) => Object.assign(record, values));
  record.destroy = vi.fn();
  return record;
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
  vi.mocked(getSystemConfig).mockResolvedValue({
    ...buildSystemConfig(),
    available_roles: ['user', 'admin'],
  } as never);
});

describe('custom claims admin', () => {
  it('lists sources with the reserved names and the budget', async () => {
    vi.mocked(CustomClaim.findAll).mockResolvedValue([buildSource()] as never);

    const res = await request(app).get('/admin/custom-claims');

    expect(res.status).toBe(200);
    expect(res.body.sources).toEqual([
      {
        sourceKind: 'instance_role',
        sourceName: 'user',
        claims: { plan: 'pro' },
        updatedAt: now.toISOString(),
      },
    ]);
    expect(res.body.reservedNames).toContain('sub');
    expect(res.body.reservedPrefixes).toEqual(['seamless_', 'org_']);
    expect(res.body.budgetBytes).toBe(1024);
  });

  it('replaces an instance role set and audits the names, not the values', async () => {
    vi.mocked(CustomClaim.create).mockImplementation(async (values: any) => buildSource(values));

    const res = await request(app)
      .put('/admin/custom-claims/instance_role/user')
      .send({ claims: { plan: 'pro', limits: { seats: 5, regions: ['us', 'eu'] } } });

    expect(res.status).toBe(200);
    expect(res.body.source.claims).toEqual({
      plan: 'pro',
      limits: { seats: 5, regions: ['us', 'eu'] },
    });
    const [event] = vi.mocked(AuthEventService.log).mock.calls[0];
    expect(event).toMatchObject({
      type: 'admin_custom_claims_updated',
      metadata: {
        sourceKind: 'instance_role',
        sourceName: 'user',
        claimNames: ['plan', 'limits'],
        added: ['plan', 'limits'],
        removed: [],
      },
    });
    expect(JSON.stringify(event.metadata)).not.toContain('"pro"');
  });

  it.each([
    ['a reserved name', { sub: 'x' }],
    ['an OpenID identity claim', { email: 'ceo@example.com' }],
    ['a reserved prefix', { org_plan: 'x' }],
    ['a name outside the alphabet', { Plan: 'x' }],
    ['a value nested deeper than 3', { deep: { a: { b: { c: { d: 1 } } } } }],
    ['a set over 1 KiB', { big: 'x'.repeat(1100) }],
  ])('refuses %s', async (_name, claims) => {
    const res = await request(app).put('/admin/custom-claims/instance_role/user').send({ claims });

    expect(res.status).toBe(400);
    expect(CustomClaim.create).not.toHaveBeenCalled();
  });

  it('refuses a role or client that does not exist', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(null);

    for (const path of [
      '/admin/custom-claims/instance_role/ghost',
      '/admin/custom-claims/organization_role/ghost',
      '/admin/custom-claims/oidc_client/ghost',
    ]) {
      const res = await request(app)
        .put(path)
        .send({ claims: { plan: 'pro' } });
      expect(res.status).toBe(404);
    }
    expect(CustomClaim.create).not.toHaveBeenCalled();
  });

  it('stores an OpenID Provider client set for the provider to apply', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue({ id: 'cli' } as never);
    vi.mocked(CustomClaim.create).mockImplementation(async (values: any) => buildSource(values));

    const res = await request(app)
      .put('/admin/custom-claims/oidc_client/cli')
      .send({ claims: { tenant: 'acme' } });

    expect(res.status).toBe(200);
    expect(res.body.source).toMatchObject({ sourceKind: 'oidc_client', sourceName: 'cli' });
  });

  it('refuses an unknown source kind', async () => {
    const res = await request(app)
      .put('/admin/custom-claims/session/x')
      .send({ claims: { plan: 'pro' } });
    expect(res.status).toBe(400);
  });

  it('reads and deletes a set, auditing the delete', async () => {
    const record = buildSource();
    vi.mocked(CustomClaim.findOne).mockResolvedValue(record as never);

    expect((await request(app).get('/admin/custom-claims/instance_role/user')).status).toBe(200);

    const deleted = await request(app).delete('/admin/custom-claims/instance_role/user');

    expect(deleted.status).toBe(200);
    expect(record.destroy).toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'admin_custom_claims_deleted',
        metadata: { sourceKind: 'instance_role', sourceName: 'user', claimNames: ['plan'] },
      }),
    );
  });

  it('answers 404 for a source with no set', async () => {
    expect((await request(app).get('/admin/custom-claims/instance_role/user')).status).toBe(404);
    expect((await request(app).delete('/admin/custom-claims/instance_role/user')).status).toBe(404);
  });
});
