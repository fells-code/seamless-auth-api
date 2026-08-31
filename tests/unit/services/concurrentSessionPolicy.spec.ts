import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Session } from '../../../src/models/sessions.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  EVICTION_REASON,
  enforceConcurrentSessionLimit,
} from '../../../src/services/concurrentSessionPolicy.js';

const NOW = new Date('2026-08-30T12:00:00.000Z');

function buildActiveSession(id: string) {
  return { id, update: vi.fn().mockResolvedValue(undefined) };
}

function req() {
  return { ip: '127.0.0.1', headers: {}, get: () => undefined } as never;
}

beforeEach(() => {
  (Session.findAll as any).mockResolvedValue([]);
});

describe('when no limit is configured', () => {
  it.each([[null], [undefined], [0]])('does nothing for %s', async (limit) => {
    const evicted = await enforceConcurrentSessionLimit({
      userId: 'user-1',
      limit: limit as number | null | undefined,
      req: req(),
      now: NOW,
    });

    expect(evicted).toBe(0);
    // Not even a lookup: an uncapped deployment should not pay for this on every
    // sign-in.
    expect(Session.findAll).not.toHaveBeenCalled();
  });

  // A negative value cannot arrive through the schema, but the enforcement runs on
  // whatever the config row holds, so it fails open rather than evicting everything.
  it('does nothing for a negative limit', async () => {
    expect(
      await enforceConcurrentSessionLimit({ userId: 'user-1', limit: -3, req: req(), now: NOW }),
    ).toBe(0);
    expect(Session.findAll).not.toHaveBeenCalled();
  });
});

describe('when the user is below the limit', () => {
  it('leaves existing sessions alone', async () => {
    (Session.findAll as any).mockResolvedValue([buildActiveSession('s-1')]);

    const evicted = await enforceConcurrentSessionLimit({
      userId: 'user-1',
      limit: 3,
      req: req(),
      now: NOW,
    });

    expect(evicted).toBe(0);
    expect(AuthEventService.log).not.toHaveBeenCalled();
  });
});

describe('when the user is at the limit', () => {
  it('revokes the oldest to make room for the new session', async () => {
    const oldest = buildActiveSession('s-oldest');
    const newer = buildActiveSession('s-newer');
    (Session.findAll as any).mockResolvedValue([oldest, newer]);

    const evicted = await enforceConcurrentSessionLimit({
      userId: 'user-1',
      limit: 2,
      req: req(),
      now: NOW,
    });

    expect(evicted).toBe(1);
    expect(oldest.update).toHaveBeenCalledWith({
      revokedAt: NOW,
      revokedReason: EVICTION_REASON,
    });
    expect(newer.update).not.toHaveBeenCalled();
  });

  it('asks for active sessions oldest first', async () => {
    (Session.findAll as any).mockResolvedValue([buildActiveSession('s-1')]);

    await enforceConcurrentSessionLimit({ userId: 'user-1', limit: 1, req: req(), now: NOW });

    expect(Session.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          userId: 'user-1',
          revokedAt: null,
          replacedBySessionId: null,
        }),
        order: [['createdAt', 'ASC']],
      }),
    );
  });

  it('records an auth event naming the session it ended', async () => {
    (Session.findAll as any).mockResolvedValue([buildActiveSession('s-oldest')]);

    await enforceConcurrentSessionLimit({ userId: 'user-1', limit: 1, req: req(), now: NOW });

    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'session_evicted',
        metadata: expect.objectContaining({ sessionId: 's-oldest', limit: 1, activeBefore: 1 }),
      }),
    );
  });
});

describe('when the user is over the limit', () => {
  // Lowering the limit leaves users above it. They should converge on the next
  // sign-in rather than shedding one session per login forever.
  it('evicts everything above the limit in one pass', async () => {
    const sessions = ['s-1', 's-2', 's-3', 's-4'].map(buildActiveSession);
    (Session.findAll as any).mockResolvedValue(sessions);

    const evicted = await enforceConcurrentSessionLimit({
      userId: 'user-1',
      limit: 2,
      req: req(),
      now: NOW,
    });

    expect(evicted).toBe(3);
    for (const session of sessions.slice(0, 3)) {
      expect(session.update).toHaveBeenCalled();
    }
    expect(sessions[3].update).not.toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledTimes(3);
  });
});

describe('when eviction fails', () => {
  // Failing an authentication over housekeeping is worse than briefly exceeding
  // the cap, so the sign-in continues.
  it('reports nothing evicted rather than throwing', async () => {
    (Session.findAll as any).mockRejectedValue(new Error('database is down'));

    await expect(
      enforceConcurrentSessionLimit({ userId: 'user-1', limit: 1, req: req(), now: NOW }),
    ).resolves.toBe(0);
  });
});
