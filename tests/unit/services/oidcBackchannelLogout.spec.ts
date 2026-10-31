import { generateKeyPairSync, verify } from 'crypto';

import { Op } from 'sequelize';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcPayloads', () => ({
  OidcPayload: {
    findAll: vi.fn(),
    upsert: vi.fn(),
    sequelize: { query: vi.fn() },
  },
}));

vi.mock('../../../src/services/authEventService', () => ({
  AuthEventService: { logContext: vi.fn() },
}));

vi.mock('../../../src/services/oidcClientRegistry', () => ({
  findActiveOidcClient: vi.fn(),
}));

vi.mock('../../../src/services/oidcAuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcAuthContext')>()),
  resolveCurrentSession: vi.fn(),
}));

vi.mock('../../../src/services/oidcProviderKeys', () => ({
  getOidcPublicJwks: vi.fn(() => ({ activeKid: 'k1', keys: [] })),
  getActiveOidcSigningKey: vi.fn(),
}));

vi.mock('../../../src/lib/oauthProviderPolicy', () => ({
  providerFetch: vi.fn(),
}));

import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { providerFetch } from '../../../src/lib/oauthProviderPolicy';
import { OidcPayload } from '../../../src/models/oidcPayloads';
import { Session } from '../../../src/models/sessions';
import { AuthEventService } from '../../../src/services/authEventService';
import { resolveCurrentSession } from '../../../src/services/oidcAuthContext';
import {
  __resetBackchannelLogoutSweep,
  BACKCHANNEL_LOGOUT_MODEL,
  recordBackchannelLogoutTargets,
  sendBackchannelLogout,
  signLogoutToken,
  startBackchannelLogoutSweep,
  sweepBackchannelLogout,
  sweepBackchannelLogoutInBackground,
} from '../../../src/services/oidcBackchannelLogout';
import { findActiveOidcClient } from '../../../src/services/oidcClientRegistry';
import { getActiveOidcSigningKey } from '../../../src/services/oidcProviderKeys';
import { buildSystemConfig } from '../../factories/systemConfigFactory';

const ISSUER = 'https://login.example.com';
const SESSION = '11111111-1111-4111-8111-111111111111';
const OTHER = '33333333-3333-4333-8333-333333333333';
const USER = '22222222-2222-4222-8222-222222222222';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const expiresAt = new Date('2030-01-01T00:00:00.000Z');

function decode(token: string) {
  const [header, claims, signature] = token.split('.');
  return {
    header: JSON.parse(Buffer.from(header, 'base64url').toString()),
    claims: JSON.parse(Buffer.from(claims, 'base64url').toString()),
    valid: verify(
      'sha256',
      Buffer.from(`${header}.${claims}`),
      publicKey,
      Buffer.from(signature, 'base64url'),
    ),
  };
}

beforeEach(() => {
  vi.mocked(OidcPayload.findAll).mockReset().mockResolvedValue([]);
  vi.mocked(OidcPayload.upsert).mockReset();
  vi.mocked(OidcPayload.sequelize!.query)
    .mockReset()
    .mockResolvedValue([] as never);
  vi.mocked(AuthEventService.logContext).mockReset();
  vi.mocked(providerFetch).mockReset();
  vi.mocked(findActiveOidcClient).mockReset();
  vi.mocked(resolveCurrentSession).mockReset();
  vi.mocked(getActiveOidcSigningKey).mockReturnValue(privateKey);
  vi.mocked(getSystemConfig).mockResolvedValue(buildSystemConfig({ oidc_issuer: ISSUER }));
  (Session as unknown as { findAll: unknown }).findAll = vi.fn(async () => [
    { id: SESSION, userId: USER },
  ]);
  __resetBackchannelLogoutSweep();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('signLogoutToken', () => {
  it('signs a back-channel logout token with the active provider key', () => {
    const { header, claims, valid } = decode(signLogoutToken(ISSUER, 'app', USER, 'sid-1'));

    expect(valid).toBe(true);
    expect(header).toEqual({ alg: 'RS256', kid: 'k1', typ: 'logout+jwt' });
    expect(claims).toEqual({
      iss: ISSUER,
      aud: 'app',
      iat: expect.any(Number),
      exp: claims.iat + 120,
      jti: expect.any(String),
      sub: USER,
      sid: 'sid-1',
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    });
    expect(claims).not.toHaveProperty('nonce');
  });

  it('refuses without an active key', () => {
    vi.mocked(getActiveOidcSigningKey).mockReturnValue(null);
    expect(() => signLogoutToken(ISSUER, 'app', USER, 'sid-1')).toThrow(/active provider/);
  });
});

describe('recordBackchannelLogoutTargets', () => {
  const hasGrant = vi.fn();

  beforeEach(() => {
    hasGrant.mockReset().mockResolvedValue(true);
  });

  it('records each client sid the session holds a grant for', async () => {
    hasGrant.mockImplementation(async (_s: string, clientId: string) => clientId === 'app');

    await recordBackchannelLogoutTargets(
      SESSION,
      { authorizations: { app: { sid: 'a1' }, stranger: { sid: 'x1' }, bad: {}, nul: null } },
      expiresAt,
      hasGrant,
    );

    expect(OidcPayload.upsert).toHaveBeenCalledTimes(1);
    expect(OidcPayload.upsert).toHaveBeenCalledWith({
      id: `${SESSION}:app`,
      model: BACKCHANNEL_LOGOUT_MODEL,
      payload: { clientId: 'app', sids: ['a1'] },
      sessionId: SESSION,
      expiresAt,
    });
  });

  it('adds a new sid to the ones already recorded and keeps the later expiry', async () => {
    const later = new Date('2031-01-01T00:00:00.000Z');
    vi.mocked(OidcPayload.findAll).mockResolvedValue([
      { id: `${SESSION}:app`, payload: { clientId: 'app', sids: ['a1'] }, expiresAt: later },
    ] as never);

    await recordBackchannelLogoutTargets(
      SESSION,
      { authorizations: { app: { sid: 'a2' } } },
      expiresAt,
      hasGrant,
    );

    expect(OidcPayload.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: { clientId: 'app', sids: ['a1', 'a2'] },
        expiresAt: later,
      }),
    );
  });

  it('writes nothing when the sid is already recorded', async () => {
    vi.mocked(OidcPayload.findAll).mockResolvedValue([
      { id: `${SESSION}:app`, payload: { clientId: 'app', sids: ['a1'] }, expiresAt },
    ] as never);

    await recordBackchannelLogoutTargets(
      SESSION,
      { authorizations: { app: { sid: 'a1' } } },
      expiresAt,
      hasGrant,
    );

    expect(hasGrant).not.toHaveBeenCalled();
    expect(OidcPayload.upsert).not.toHaveBeenCalled();
  });

  it('keeps only the latest sids for a client', async () => {
    const sids = Array.from({ length: 10 }, (_, i) => `s${i}`);
    vi.mocked(OidcPayload.findAll).mockResolvedValue([
      { id: `${SESSION}:app`, payload: { clientId: 'app', sids }, expiresAt },
    ] as never);

    await recordBackchannelLogoutTargets(
      SESSION,
      { authorizations: { app: { sid: 'new' } } },
      expiresAt,
      hasGrant,
    );

    expect(OidcPayload.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ payload: { clientId: 'app', sids: [...sids.slice(1), 'new'] } }),
    );
  });

  it('ignores a session payload without authorizations', async () => {
    await recordBackchannelLogoutTargets(SESSION, {}, expiresAt, hasGrant);
    await recordBackchannelLogoutTargets(SESSION, { authorizations: 'x' }, expiresAt, hasGrant);

    expect(OidcPayload.findAll).not.toHaveBeenCalled();
  });
});

describe('sendBackchannelLogout', () => {
  function claimed(rows: { payload: Record<string, unknown>; sessionId: string }[]) {
    vi.mocked(OidcPayload.sequelize!.query).mockResolvedValue(rows as never);
  }

  it('claims the rows in one statement and posts a logout token per sid', async () => {
    claimed([{ payload: { clientId: 'app', sids: ['a1'] }, sessionId: SESSION }]);
    vi.mocked(findActiveOidcClient).mockResolvedValue({
      id: 'app',
      backchannelLogoutUri: 'https://app.example.com/logout',
    } as never);
    vi.mocked(providerFetch).mockResolvedValue(new Response(null, { status: 200 }));

    expect(await sendBackchannelLogout([SESSION, 'not-a-uuid'])).toBe(1);

    const [sql, options] = vi.mocked(OidcPayload.sequelize!.query).mock.calls[0];
    expect(sql).toMatch(/DELETE FROM public\.oidc_payloads[\s\S]*RETURNING/);
    expect(options).toMatchObject({
      replacements: { model: BACKCHANNEL_LOGOUT_MODEL, sessionIds: [SESSION] },
    });

    const [uri, init] = vi.mocked(providerFetch).mock.calls[0];
    expect(uri).toBe('https://app.example.com/logout');
    expect(init).toMatchObject({
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    const token = new URLSearchParams(String(init?.body)).get('logout_token')!;
    expect(decode(token).claims).toMatchObject({ aud: 'app', sub: USER, sid: 'a1' });
    expect(AuthEventService.logContext).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_backchannel_logout_sent',
        userId: USER,
        sessionId: SESSION,
        metadata: { clientId: 'app', status: 200 },
      }),
    );
  });

  it('audits a delivery the client refused or that failed', async () => {
    claimed([{ payload: { clientId: 'app', sids: ['a1', 'a2'] }, sessionId: SESSION }]);
    vi.mocked(findActiveOidcClient).mockResolvedValue({
      id: 'app',
      backchannelLogoutUri: 'https://app.example.com/logout',
    } as never);
    vi.mocked(providerFetch)
      .mockResolvedValueOnce(new Response('no', { status: 400 }))
      .mockRejectedValueOnce(Object.assign(new Error('t'), { name: 'TimeoutError' }));

    await sendBackchannelLogout([SESSION]);

    expect(AuthEventService.logContext).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_backchannel_logout_failed',
        metadata: { clientId: 'app', status: 400 },
      }),
    );
    expect(AuthEventService.logContext).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_backchannel_logout_failed',
        metadata: { clientId: 'app', error: 'TimeoutError' },
      }),
    );
  });

  it('sends nothing to a client without a back-channel URI, or that is gone', async () => {
    claimed([
      { payload: { clientId: 'app', sids: ['a1'] }, sessionId: SESSION },
      { payload: { clientId: 'gone', sids: ['g1'] }, sessionId: SESSION },
      { payload: { broken: true }, sessionId: SESSION },
      { payload: { clientId: 'app', sids: ['a1'] }, sessionId: OTHER },
    ]);
    vi.mocked(findActiveOidcClient).mockImplementation(async (id) =>
      id === 'app' ? ({ id: 'app', backchannelLogoutUri: null } as never) : null,
    );

    expect(await sendBackchannelLogout([SESSION, OTHER])).toBe(4);
    expect(providerFetch).not.toHaveBeenCalled();
  });

  it('does nothing when nothing is claimed', async () => {
    expect(await sendBackchannelLogout([])).toBe(0);
    expect(OidcPayload.sequelize!.query).not.toHaveBeenCalled();

    expect(await sendBackchannelLogout([SESSION])).toBe(0);
    expect(findActiveOidcClient).not.toHaveBeenCalled();
  });

  it('leaves the rows in place while no issuer is set', async () => {
    vi.mocked(getSystemConfig).mockResolvedValue(buildSystemConfig({ oidc_issuer: '' }));
    expect(await sendBackchannelLogout([SESSION])).toBe(0);
    expect(OidcPayload.sequelize!.query).not.toHaveBeenCalled();
  });
});

describe('sweepBackchannelLogout', () => {
  it('sends only for recorded sessions that are no longer live', async () => {
    vi.mocked(OidcPayload.findAll).mockResolvedValue([
      { id: 'a', sessionId: SESSION },
      { id: 'b', sessionId: SESSION },
      { id: 'c', sessionId: OTHER },
      { id: 'd', sessionId: null },
    ] as never);
    vi.mocked(resolveCurrentSession).mockImplementation(async (id) =>
      id === OTHER ? ({ id } as never) : null,
    );

    await sweepBackchannelLogout();

    expect(resolveCurrentSession).toHaveBeenCalledTimes(2);
    expect(vi.mocked(OidcPayload.sequelize!.query).mock.calls[0][1]).toMatchObject({
      replacements: { sessionIds: [SESSION] },
    });
  });

  it('walks the table a batch at a time', async () => {
    const batch = Array.from({ length: 500 }, (_, i) => ({
      id: `row-${String(i).padStart(3, '0')}`,
      sessionId: OTHER,
    }));
    vi.mocked(resolveCurrentSession).mockResolvedValue({ id: OTHER } as never);
    vi.mocked(OidcPayload.findAll)
      .mockResolvedValueOnce(batch as never)
      .mockResolvedValue([]);

    await sweepBackchannelLogout();
    await sweepBackchannelLogout();
    await sweepBackchannelLogout();

    const cursors = vi
      .mocked(OidcPayload.findAll)
      .mock.calls.map(([options]) => (options!.where as { id: Record<symbol, string> }).id[Op.gt]);
    expect(cursors).toEqual(['', 'row-499', '']);
  });

  it('runs one background sweep at a time', async () => {
    let release!: (rows: never[]) => void;
    vi.mocked(OidcPayload.findAll).mockReturnValueOnce(
      new Promise((resolve) => (release = resolve)) as never,
    );
    sweepBackchannelLogoutInBackground();
    sweepBackchannelLogoutInBackground();
    expect(OidcPayload.findAll).toHaveBeenCalledTimes(1);
    release([]);
    await new Promise((resolve) => setImmediate(resolve));
    sweepBackchannelLogoutInBackground();
    expect(OidcPayload.findAll).toHaveBeenCalledTimes(2);
    await new Promise((resolve) => setImmediate(resolve));
  });

  it('logs a sweep that fails rather than throwing', async () => {
    vi.mocked(OidcPayload.findAll).mockRejectedValue(new Error('db down'));
    sweepBackchannelLogoutInBackground();
    await new Promise((resolve) => setImmediate(resolve));
  });

  it('runs on an interval', async () => {
    vi.useFakeTimers();
    startBackchannelLogoutSweep();
    await vi.advanceTimersByTimeAsync(30_000);

    expect(OidcPayload.findAll).toHaveBeenCalled();
  });
});
