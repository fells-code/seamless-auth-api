import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { getSequelize } from '../../../src/models/index.js';
import { Organization } from '../../../src/models/organizations.js';
import { CoverageReportResponseSchema } from '../../../src/schemas/coverageReport.js';
import { validateBearerToken } from '../../../src/services/sessionService.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

// Driven through the real bearer and admin checks, which every other admin spec stubs out.
vi.unmock('../../../src/middleware/attachAuthMiddleware.js');
vi.unmock('../../../src/middleware/requireAdmin.js');

vi.mock('../../../src/models/index.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/models/index.js')>()),
  getSequelize: vi.fn(),
}));

const PATH = '/admin/reports/authentication-coverage';
const orgId = '11111111-1111-4111-8111-111111111111';
const query = vi.fn();
let app: Application;

function asRoles(roles: string[]) {
  vi.mocked(validateBearerToken).mockResolvedValue({
    user: { id: 'admin-1', email: 'admin@example.gov', roles },
    sessionId: 'session-1',
  } as never);
}

beforeAll(async () => {
  const { createApp } = await import('../../../src/app.js');

  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  query.mockReset();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
  vi.mocked(getSystemConfig).mockResolvedValue(
    buildSystemConfig({
      login_methods: ['passkey', 'email_otp'],
      authenticator_policy: {
        attachment: 'any',
        userVerification: 'required',
        attestation: 'none',
        requireKnownAuthenticator: false,
        syncedPasskeys: 'allow',
        aaguidAllowList: [],
        aaguidDenyList: [],
      },
    }) as never,
  );
  asRoles(['admin:read']);

  query.mockImplementation(async (sql: string) => {
    if (sql.includes('unnest(')) return [{ users: 4, passkeyUsers: 3 }];
    if (sql.includes('FROM organizations o')) {
      return [
        { organizationId: orgId, name: 'Public Works', users: 3, passkeyUsers: 3 },
        { organizationId: null, name: null, users: 1, passkeyUsers: 0 },
      ];
    }
    if (sql.includes('"backupEligible"')) {
      return [
        {
          aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
          credentials: 3,
          users: 3,
          backupEligible: 3,
          backedUp: 3,
        },
      ];
    }
    return [{ method: 'passkey', signIns: 12, users: 3 }];
  });
});

describe('GET /admin/reports/authentication-coverage', () => {
  it('requires a bearer token', async () => {
    const res = await request(app).get(PATH);

    expect(res.status).toBe(401);
    expect(query).not.toHaveBeenCalled();
  });

  it('requires an admin role', async () => {
    asRoles(['user']);

    const res = await request(app).get(PATH).set('Authorization', 'Bearer token');

    expect(res.status).toBe(403);
    expect(query).not.toHaveBeenCalled();
  });

  it('validates the token as an access token', async () => {
    await request(app).get(PATH).set('Authorization', 'Bearer token');

    expect(validateBearerToken).toHaveBeenCalledWith('token', 'access');
  });

  it('returns the report as JSON', async () => {
    const res = await request(app)
      .get(`${PATH}?from=2026-01-01&to=2026-01-31`)
      .set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    expect(CoverageReportResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body.period).toEqual({ from: '2026-01-01', to: '2026-01-31' });
    expect(res.body.bucket).toBe('month');
    expect(res.body.coverage).toEqual({ users: 4, passkeyUsers: 3, percent: 75 });
    expect(res.body.policy.loginMethods).toEqual(['passkey', 'email_otp']);
    expect(res.body.byOrganization).toHaveLength(2);
    expect(res.body.trend).toEqual([
      { start: '2026-01-01', end: '2026-01-31', users: 4, passkeyUsers: 3, percent: 75 },
    ]);
    expect(res.body.authenticatorMix[0].name).toBe('Google Password Manager');
    expect(res.body.signInMix).toEqual(expect.objectContaining({ total: 12, percent: 100 }));
  });

  it('returns the report as a CSV attachment', async () => {
    const res = await request(app)
      .get(`${PATH}?from=2026-01-01&to=2026-01-31&format=csv`)
      .set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(res.headers['content-disposition']).toBe(
      'attachment; filename="authentication-coverage-2026-01-01-to-2026-01-31.csv"',
    );
    expect(res.text.split('\r\n')).toEqual(
      expect.arrayContaining([
        'Authentication coverage report',
        'Phishing-resistant only,false',
        'All users,,4,3,75',
        `Public Works,${orgId},3,3,100`,
        'No organization,,1,0,0',
      ]),
    );
  });

  it('scopes the report to an organization', async () => {
    vi.mocked(Organization.findByPk).mockResolvedValue({ id: orgId } as never);

    const res = await request(app)
      .get(`${PATH}?organizationId=${orgId}&bucket=week`)
      .set('Authorization', 'Bearer token');

    expect(res.status).toBe(200);
    expect(res.body.organizationId).toBe(orgId);
    expect(res.body.bucket).toBe('week');
  });

  it('answers 404 for an unknown organization', async () => {
    vi.mocked(Organization.findByPk).mockResolvedValue(null as never);

    const res = await request(app)
      .get(`${PATH}?organizationId=${orgId}`)
      .set('Authorization', 'Bearer token');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Organization not found' });
    expect(query).not.toHaveBeenCalled();
  });

  it.each([
    'from=2026-13-01',
    'from=2026-05-01&to=2026-04-01',
    'from=2015-01-01&to=2026-01-01',
    'bucket=day',
    'format=pdf',
    'organizationId=not-a-uuid',
  ])('rejects %s', async (search) => {
    const res = await request(app).get(`${PATH}?${search}`).set('Authorization', 'Bearer token');

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(query).not.toHaveBeenCalled();
  });
});
