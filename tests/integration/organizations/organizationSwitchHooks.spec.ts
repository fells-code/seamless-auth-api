import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/services/loginHookService.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/services/loginHookService.js')>();
  return { ...actual, runLoginHook: vi.fn(async () => ({ outcome: 'skipped' })) };
});

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { switchOrganization } from '../../../src/controllers/organizations.js';
import { signAccessToken } from '../../../src/lib/token.js';
import { OrganizationMembership } from '../../../src/models/organizationMemberships.js';
import { Organization } from '../../../src/models/organizations.js';
import { Session } from '../../../src/models/sessions.js';
import { runLoginHook } from '../../../src/services/loginHookService.js';
import {
  buildOrganization,
  buildOrganizationMembership,
  testOrganizationId,
} from '../../factories/organizationFactory';
import { buildSession } from '../../factories/sessionFactory';

const user = { id: 'user-1', email: 'test@example.com', phone: null, roles: ['user'] };

function call(overrides: Record<string, unknown> = {}) {
  const req: any = {
    user: { ...user, ...overrides },
    sessionId: 'session-1',
    params: { organizationId: testOrganizationId },
  };
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return { req, res };
}

let session: ReturnType<typeof buildSession>;

beforeEach(() => {
  session = buildSession({ id: 'session-1', userId: 'user-1', recovery: false });
  vi.mocked(Organization.findByPk).mockResolvedValue(buildOrganization() as never);
  vi.mocked(OrganizationMembership.findOne).mockResolvedValue(
    buildOrganizationMembership() as never,
  );
  vi.mocked(Session.findOne).mockResolvedValue(session as never);
  vi.mocked(signAccessToken).mockResolvedValue('organization-access-token');
  vi.mocked(getSystemConfig).mockResolvedValue({ access_token_ttl: '15m' } as never);
});

describe('organization switch and the pre_token hook', () => {
  it('calls pre_token with the new organization and its roles, and keeps the claims', async () => {
    vi.mocked(runLoginHook).mockResolvedValueOnce({ outcome: 'allowed', claims: { plan: 'pro' } });
    const { req, res } = call();

    await switchOrganization(req, res);

    expect(runLoginHook).toHaveBeenCalledWith('pre_token', {
      user,
      method: null,
      organizationId: testOrganizationId,
      organizationRoles: ['owner', 'admin'],
      req,
    });
    expect(session.update).toHaveBeenCalledWith({
      organizationId: testOrganizationId,
      hookClaims: { plan: 'pro' },
    });
    expect(vi.mocked(signAccessToken).mock.calls[0][4]).toMatchObject({
      customClaims: { plan: 'pro' },
    });
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ token: 'organization-access-token' }),
    );
  });

  it('passes no roles for a membership that holds none', async () => {
    vi.mocked(OrganizationMembership.findOne).mockResolvedValue(
      buildOrganizationMembership({ roles: null, scopes: ['organization:read'] }) as never,
    );
    const { req, res } = call();

    await switchOrganization(req, res);

    expect(vi.mocked(runLoginHook).mock.calls[0][1]).toMatchObject({ organizationRoles: [] });
  });

  it('refuses the switch on a deny, leaving the session where it was', async () => {
    vi.mocked(runLoginHook).mockResolvedValueOnce({ outcome: 'denied', userMessage: null });
    const { req, res } = call();

    await switchOrganization(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'login_denied' });
    expect(session.update).not.toHaveBeenCalled();
    expect(signAccessToken).not.toHaveBeenCalled();
  });

  it('refuses the switch when a closed hook fails', async () => {
    vi.mocked(runLoginHook).mockResolvedValueOnce({ outcome: 'failed_closed' });
    const { req, res } = call();

    await switchOrganization(req, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(session.update).not.toHaveBeenCalled();
  });

  it('never calls a hook for a recovery session', async () => {
    session.recovery = true;
    const { req, res } = call();

    await switchOrganization(req, res);

    expect(runLoginHook).not.toHaveBeenCalled();
    expect(session.update).toHaveBeenCalledWith({
      organizationId: testOrganizationId,
      hookClaims: null,
    });
  });

  it('never calls a hook for a break-glass administrator', async () => {
    vi.stubEnv('BREAK_GLASS_EMAILS', 'test@example.com');
    const { req, res } = call({ roles: ['admin:write'] });

    await switchOrganization(req, res);

    expect(runLoginHook).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ token: 'organization-access-token' }),
    );
  });
});
