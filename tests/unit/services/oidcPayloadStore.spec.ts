import { Op } from 'sequelize';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcPayloads', () => ({
  OidcPayload: {
    upsert: vi.fn(),
    findOne: vi.fn(),
    update: vi.fn(),
    destroy: vi.fn(),
    sequelize: { query: vi.fn() },
  },
}));

vi.mock('../../../src/services/oidcAuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oidcAuthContext')>()),
  resolveCurrentSession: vi.fn(),
}));

vi.mock('../../../src/services/oidcBackchannelLogout', () => ({
  recordBackchannelLogoutTargets: vi.fn(),
  sendBackchannelLogoutForClient: vi.fn(),
}));

import { OidcPayload } from '../../../src/models/oidcPayloads';
import {
  recordBackchannelLogoutTargets,
  sendBackchannelLogoutForClient,
} from '../../../src/services/oidcBackchannelLogout';
import { resolveCurrentSession } from '../../../src/services/oidcAuthContext';
import {
  DEVICE_CODE_EXPIRED_GRACE_MS,
  bindOidcSession,
  claimOAuthStateUse,
  consumeOidcPayload,
  destroyOidcPayload,
  ExpiryTooLongError,
  findOidcPayload,
  findOidcPayloadByUid,
  findGrantBoundSession,
  findOidcPayloadByUserCode,
  hasOidcGrantForSession,
  hasOidcGrantForUser,
  InvalidSessionIdError,
  isOidcSessionBound,
  MAX_EXPIRES_IN_SECONDS,
  purgeExpiredOidcPayloads,
  revokeOidcPayloadsByGrant,
  startOidcPayloadPurge,
  upsertOidcPayload,
} from '../../../src/services/oidcPayloadStore';

const SESSION = '11111111-1111-4111-8111-111111111111';
const expiresAt = new Date('2030-01-01T00:00:00.000Z');

describe('upsertOidcPayload', () => {
  it('stores the record with its lookup columns', async () => {
    const result = await upsertOidcPayload('Grant', 'g1', {
      payload: { grantId: 'g1', uid: 'u1', userCode: 'ABCD', other: 1 },
      expiresIn: 60,
      sessionId: SESSION,
    });

    expect(result).toEqual({ created: true });
    expect(OidcPayload.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'g1',
        model: 'Grant',
        grantId: 'g1',
        uid: 'u1',
        userCode: 'ABCD',
        sessionId: SESSION,
        expiresAt: expect.any(Date),
      }),
    );
  });

  it('records who to tell at logout when a provider Session is stored for a session', async () => {
    const payload = { authorizations: { app: { sid: 's' } } };
    await upsertOidcPayload('Session', 's1', { payload, expiresIn: 60, sessionId: SESSION });

    expect(recordBackchannelLogoutTargets).toHaveBeenCalledWith(
      SESSION,
      payload,
      expect.any(Date),
      hasOidcGrantForSession,
    );
  });

  it('records nothing for other models or a Session without a first-party session', async () => {
    vi.mocked(recordBackchannelLogoutTargets).mockClear();
    await upsertOidcPayload('Grant', 'g1', { payload: {}, expiresIn: 60, sessionId: SESSION });
    await upsertOidcPayload('Session', 's1', { payload: {}, expiresIn: 60 });

    expect(recordBackchannelLogoutTargets).not.toHaveBeenCalled();
  });

  it('leaves lookup columns empty when the payload has none', async () => {
    await upsertOidcPayload('Session', 's1', { payload: { grantId: '' }, expiresIn: 60 });

    expect(OidcPayload.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ grantId: null, uid: null, userCode: null, sessionId: null }),
    );
  });

  it('refuses a session id that is not one', async () => {
    await expect(
      upsertOidcPayload('Session', 's1', { payload: {}, expiresIn: 60, sessionId: 'nope' }),
    ).rejects.toBeInstanceOf(InvalidSessionIdError);
  });

  it('refuses an expiry longer than any provider record lives', async () => {
    await expect(
      upsertOidcPayload('Session', 's1', { payload: {}, expiresIn: MAX_EXPIRES_IN_SECONDS + 1 }),
    ).rejects.toBeInstanceOf(ExpiryTooLongError);
  });

  it('inserts replay detection only if absent', async () => {
    vi.mocked(OidcPayload.sequelize!.query).mockResolvedValueOnce([{ id: 'j1' }] as never);
    expect(
      await upsertOidcPayload('ReplayDetection', 'j1', { payload: { iss: 'x' }, expiresIn: 60 }),
    ).toEqual({ created: true });

    vi.mocked(OidcPayload.sequelize!.query).mockResolvedValueOnce([] as never);
    expect(
      await upsertOidcPayload('ReplayDetection', 'j1', { payload: { iss: 'x' }, expiresIn: 60 }),
    ).toEqual({ created: false });

    expect(OidcPayload.upsert).not.toHaveBeenCalled();
    expect(vi.mocked(OidcPayload.sequelize!.query).mock.calls[0][0]).toMatch(/ON CONFLICT/);
  });
});

describe('claimOAuthStateUse', () => {
  it('records the state under its own model only if absent', async () => {
    vi.mocked(OidcPayload.sequelize!.query).mockResolvedValueOnce([{ id: 'h1' }] as never);
    expect(await claimOAuthStateUse('h1', expiresAt)).toBe(true);

    vi.mocked(OidcPayload.sequelize!.query).mockResolvedValueOnce([] as never);
    expect(await claimOAuthStateUse('h1', expiresAt)).toBe(false);

    expect(vi.mocked(OidcPayload.sequelize!.query).mock.calls[0][1]).toEqual(
      expect.objectContaining({
        replacements: expect.objectContaining({
          id: 'h1',
          model: 'OAuthStateReplay',
          payload: '{}',
          expiresAt,
        }),
      }),
    );
  });
});

describe('finding records', () => {
  beforeEach(() => {
    vi.mocked(resolveCurrentSession).mockResolvedValue({ id: SESSION } as never);
  });

  it('returns a live record', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValue({
      model: 'Grant',
      id: 'g1',
      payload: { a: 1 },
      sessionId: null,
      expiresAt,
      consumedAt: null,
    } as never);

    expect(await findOidcPayload('Grant', 'g1')).toEqual({
      payload: { a: 1 },
      sessionId: null,
      expiresAt: expiresAt.toISOString(),
      consumedAt: null,
    });
    expect(vi.mocked(OidcPayload.findOne).mock.calls[0][0]).toMatchObject({
      where: { model: 'Grant', id: 'g1', expiresAt: { [Op.gt]: expect.any(Date) } },
    });
  });

  it('reports when a record was consumed', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValue({
      payload: {},
      sessionId: SESSION,
      expiresAt,
      consumedAt: expiresAt,
    } as never);

    expect((await findOidcPayloadByUid('Interaction', 'u1'))?.consumedAt).toBe(
      expiresAt.toISOString(),
    );
  });

  it('hides a record whose session is no longer live', async () => {
    vi.mocked(resolveCurrentSession).mockResolvedValue(null);
    vi.mocked(OidcPayload.findOne).mockResolvedValue({
      payload: {},
      sessionId: SESSION,
      expiresAt,
      consumedAt: null,
    } as never);

    expect(await findOidcPayloadByUserCode('DeviceCode', 'ABCD')).toBeNull();
  });

  it('returns null for a missing record', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValue(null);
    expect(await findOidcPayload('Grant', 'g1')).toBeNull();
  });

  it('reads a device code by id for a grace window past its expiry', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValue(null);
    const before = Date.now();

    await findOidcPayload('DeviceCode', 'd1');
    await findOidcPayloadByUserCode('DeviceCode', 'ABCD');

    const [byId, byUserCode] = vi
      .mocked(OidcPayload.findOne)
      .mock.calls.map((call) => (call[0] as any).where.expiresAt[Op.gt].getTime());
    expect(byId).toBeLessThanOrEqual(Date.now() - DEVICE_CODE_EXPIRED_GRACE_MS);
    expect(byId).toBeGreaterThanOrEqual(before - DEVICE_CODE_EXPIRED_GRACE_MS);
    expect(byUserCode).toBeGreaterThanOrEqual(before);
  });
});

describe('bindOidcSession', () => {
  it('stores the binding under a model the edge cannot name, for the longest grant', async () => {
    vi.useFakeTimers({ now: new Date('2030-01-01T00:00:00.000Z') });
    await bindOidcSession(SESSION, 'u1', 'app');
    vi.useRealTimers();

    expect(OidcPayload.upsert).toHaveBeenCalledWith({
      id: `${SESSION}:app`,
      model: 'SessionBinding',
      payload: { accountId: 'u1', clientId: 'app' },
      grantId: null,
      userCode: null,
      uid: null,
      sessionId: SESSION,
      expiresAt: new Date(Date.parse('2030-01-01T00:00:00.000Z') + MAX_EXPIRES_IN_SECONDS * 1000),
    });
  });
});

describe('isOidcSessionBound', () => {
  it('needs a live binding for the session', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValueOnce({ payload: {} } as never);
    expect(await isOidcSessionBound(SESSION)).toBe(true);
    expect(vi.mocked(OidcPayload.findOne).mock.calls[0][0]).toMatchObject({
      where: { model: 'SessionBinding', sessionId: SESSION },
    });

    vi.mocked(OidcPayload.findOne).mockResolvedValueOnce(null);
    expect(await isOidcSessionBound(SESSION)).toBe(false);
  });

  it('refuses a malformed session id without a query', async () => {
    expect(await isOidcSessionBound('nope')).toBe(false);
    expect(OidcPayload.findOne).not.toHaveBeenCalled();
  });
});

const binding = (payload: Record<string, unknown>) => ({ payload }) as never;

describe('hasOidcGrantForSession', () => {
  it('needs the API binding and a live grant for this client stored against the session', async () => {
    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(binding({ clientId: 'app' }))
      .mockResolvedValueOnce({ payload: { clientId: 'app' } } as never);
    expect(await hasOidcGrantForSession(SESSION, 'app')).toBe(true);
    expect(vi.mocked(OidcPayload.findOne).mock.calls[0][0]).toMatchObject({
      where: { model: 'SessionBinding', id: `${SESSION}:app` },
    });
    expect(vi.mocked(OidcPayload.findOne).mock.calls[1][0]).toMatchObject({
      where: { model: 'Grant', sessionId: SESSION, payload: { clientId: 'app' } },
    });

    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(binding({ clientId: 'app' }))
      .mockResolvedValueOnce({ payload: { clientId: 'other' } } as never);
    expect(await hasOidcGrantForSession(SESSION, 'app')).toBe(false);

    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(binding({ clientId: 'app' }))
      .mockResolvedValueOnce(null);
    expect(await hasOidcGrantForSession(SESSION, 'app')).toBe(false);
  });

  it('ignores a grant the edge stored for a session the API never bound', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValueOnce(null);
    expect(await hasOidcGrantForSession(SESSION, 'app')).toBe(false);
    expect(OidcPayload.findOne).toHaveBeenCalledTimes(1);
  });

  it('refuses a malformed session id without a query', async () => {
    expect(await hasOidcGrantForSession('nope', 'app')).toBe(false);
    expect(OidcPayload.findOne).not.toHaveBeenCalled();
  });
});

describe('hasOidcGrantForUser', () => {
  it('needs the API binding and a live grant held by the user for this client', async () => {
    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(binding({ accountId: SESSION, clientId: 'app' }))
      .mockResolvedValueOnce({ payload: { accountId: SESSION, clientId: 'app' } } as never);
    expect(await hasOidcGrantForUser(SESSION, 'app')).toBe(true);
    expect(vi.mocked(OidcPayload.findOne).mock.calls[0][0]).toMatchObject({
      where: { model: 'SessionBinding', payload: { accountId: SESSION, clientId: 'app' } },
    });
    expect(vi.mocked(OidcPayload.findOne).mock.calls[1][0]).toMatchObject({
      where: { model: 'Grant', payload: { accountId: SESSION, clientId: 'app' } },
    });

    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(binding({ accountId: SESSION, clientId: 'app' }))
      .mockResolvedValueOnce({ payload: { accountId: SESSION, clientId: 'other' } } as never);
    expect(await hasOidcGrantForUser(SESSION, 'app')).toBe(false);

    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(binding({ accountId: SESSION, clientId: 'app' }))
      .mockResolvedValueOnce(null);
    expect(await hasOidcGrantForUser(SESSION, 'app')).toBe(false);
  });

  it('ignores a grant the edge stored for a user who never signed in to the client', async () => {
    vi.mocked(OidcPayload.findOne).mockResolvedValueOnce(null);
    expect(await hasOidcGrantForUser(SESSION, 'app')).toBe(false);

    vi.mocked(OidcPayload.findOne).mockResolvedValueOnce(
      binding({ accountId: SESSION, clientId: 'other' }),
    );
    expect(await hasOidcGrantForUser(SESSION, 'app')).toBe(false);
    expect(OidcPayload.findOne).toHaveBeenCalledTimes(2);
  });

  it('refuses a malformed user id without a query', async () => {
    expect(await hasOidcGrantForUser('nope', 'app')).toBe(false);
    expect(OidcPayload.findOne).not.toHaveBeenCalled();
  });
});

describe('findGrantBoundSession', () => {
  it('returns the current session only when it holds a grant for the client', async () => {
    vi.mocked(resolveCurrentSession).mockResolvedValue({ id: SESSION, userId: 'u1' } as never);
    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce(binding({ clientId: 'app' }))
      .mockResolvedValueOnce({ payload: { clientId: 'app' } } as never);
    expect(await findGrantBoundSession(SESSION, 'app')).toEqual({ id: SESSION, userId: 'u1' });

    vi.mocked(OidcPayload.findOne).mockResolvedValueOnce(null);
    expect(await findGrantBoundSession(SESSION, 'app')).toBeNull();
  });

  it('returns null for a dead session without looking for a grant', async () => {
    vi.mocked(resolveCurrentSession).mockResolvedValue(null);
    expect(await findGrantBoundSession(SESSION, 'app')).toBeNull();
    expect(OidcPayload.findOne).not.toHaveBeenCalled();
  });
});

describe('changing records', () => {
  it('consumes once, in one conditional statement, and says whether this call did', async () => {
    vi.mocked(OidcPayload.update).mockResolvedValueOnce([1] as never);
    expect(await consumeOidcPayload('RefreshToken', 'r1')).toBe(true);
    expect(OidcPayload.update).toHaveBeenCalledWith(
      { consumedAt: expect.any(Date) },
      {
        where: {
          model: 'RefreshToken',
          id: 'r1',
          consumedAt: { [Op.is]: null },
          expiresAt: { [Op.gt]: expect.any(Date) },
        },
      },
    );

    // The second of two racing refreshes: the row already had consumedAt.
    vi.mocked(OidcPayload.update).mockResolvedValueOnce([0] as never);
    expect(await consumeOidcPayload('RefreshToken', 'r1')).toBe(false);
  });

  it('destroys one record, or every record of a grant', async () => {
    await destroyOidcPayload('Session', 's1');
    await revokeOidcPayloadsByGrant('RefreshToken', 'g1');

    expect(OidcPayload.destroy).toHaveBeenCalledWith({ where: { model: 'Session', id: 's1' } });
    expect(OidcPayload.destroy).toHaveBeenCalledWith({
      where: { model: 'RefreshToken', grantId: 'g1' },
    });
  });

  it('tells the application when its grant ends while its session lives on', async () => {
    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce({ payload: { clientId: 'app' }, sessionId: SESSION } as never)
      .mockResolvedValueOnce(null);

    await destroyOidcPayload('Grant', 'g1');

    expect(OidcPayload.destroy).toHaveBeenCalledWith({ where: { model: 'Grant', id: 'g1' } });
    expect(sendBackchannelLogoutForClient).toHaveBeenCalledWith(SESSION, 'app');
    expect(vi.mocked(OidcPayload.destroy).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(sendBackchannelLogoutForClient).mock.invocationCallOrder[0],
    );
  });

  it('tells no one while another grant still signs the application in on the session', async () => {
    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce({ payload: { clientId: 'app' }, sessionId: SESSION } as never)
      .mockResolvedValueOnce({ payload: { clientId: 'app' } } as never)
      .mockResolvedValueOnce({ payload: { clientId: 'app' } } as never);

    await destroyOidcPayload('Grant', 'g1');

    expect(sendBackchannelLogoutForClient).not.toHaveBeenCalled();
  });

  it('tells no one for a grant without a session or client, or one that is gone', async () => {
    vi.mocked(OidcPayload.findOne)
      .mockResolvedValueOnce({ payload: { clientId: 'app' }, sessionId: null } as never)
      .mockResolvedValueOnce({ payload: {}, sessionId: SESSION } as never)
      .mockResolvedValueOnce(null);

    await destroyOidcPayload('Grant', 'g1');
    await destroyOidcPayload('Grant', 'g2');
    await destroyOidcPayload('Grant', 'g3');

    expect(OidcPayload.destroy).toHaveBeenCalledTimes(3);
    expect(sendBackchannelLogoutForClient).not.toHaveBeenCalled();
  });

  it('purges expired records', async () => {
    vi.mocked(OidcPayload.destroy).mockResolvedValue(3 as never);
    const now = new Date();

    expect(await purgeExpiredOidcPayloads(now)).toBe(3);
    expect(OidcPayload.destroy).toHaveBeenCalledWith({
      where: {
        [Op.or]: [
          { model: { [Op.ne]: 'DeviceCode' }, expiresAt: { [Op.lte]: now } },
          {
            expiresAt: {
              [Op.lte]: new Date(now.getTime() - DEVICE_CODE_EXPIRED_GRACE_MS),
            },
          },
        ],
      },
    });
  });
});

describe('startOidcPayloadPurge', () => {
  it('purges on an interval and survives a failure', async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(OidcPayload.destroy)
        .mockResolvedValueOnce(2 as never)
        .mockResolvedValueOnce(0 as never)
        .mockRejectedValueOnce(new Error('db down'));

      startOidcPayloadPurge();
      await vi.advanceTimersByTimeAsync(60 * 60 * 1000 * 3);

      expect(OidcPayload.destroy).toHaveBeenCalledTimes(3);
    } finally {
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });
});
