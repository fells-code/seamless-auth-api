import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AccountRecoveryRequest } from '../../../src/models/accountRecoveryRequests.js';
import { AuthFailure } from '../../../src/models/authFailures.js';
import { Session } from '../../../src/models/sessions.js';
import { User } from '../../../src/models/users.js';
import {
  cancelRecoveryByToken,
  completeRecovery,
  findRecoveryForAttempt,
  MAX_RECOVERY_CODE_ATTEMPTS,
  RECOVERY_FAILURE_BUDGET,
  RECOVERY_FAILURE_WINDOW_MS,
  recoveryStatus,
  startRecovery,
  supersedeOtherRecoveries,
  verifyRecovery,
  voidUnannouncedRecovery,
} from '../../../src/services/accountRecoveryService.js';
import {
  installAccountRecoveryStore,
  installAuthFailureStore,
} from '../../factories/accountRecoveryStore.js';

const HOUR = 3600;
let rows: ReturnType<typeof installAccountRecoveryStore>;
let failures: ReturnType<typeof installAuthFailureStore>;

beforeEach(() => {
  rows = installAccountRecoveryStore();
  failures = installAuthFailureStore();
  (Session.update as any).mockResolvedValue([3]);
});

afterEach(() => {
  vi.useRealTimers();
});

function wrong(code: string) {
  return code === 'AAAAAA' ? 'BBBBBB' : 'AAAAAA';
}

async function open(attemptId = 'attempt-1', channel: 'email' | 'phone' = 'email') {
  const code = (await startRecovery('user-1', channel, attemptId))!;
  const result = await verifyRecovery('user-1', attemptId, code, HOUR);
  if (result.outcome !== 'opened') throw new Error(`expected opened, got ${result.outcome}`);
  return result;
}

describe('startRecovery', () => {
  it('stores a six-letter email code only as a hash, bound to the attempt', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;

    expect(code).toMatch(/^[A-Z]{6}$/);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ state: 'awaiting_code', codeAttemptId: 'attempt-1' });
    expect(rows[0].codeHash).toMatch(/^sha256:/);
    expect(rows[0].codeHash).not.toContain(code);
    expect(+rows[0].codeExpiresAt - Date.now()).toBeGreaterThan(9 * 60 * 1000);
  });

  it('sends an eight-digit code by phone', async () => {
    expect(await startRecovery('user-1', 'phone', 'attempt-1')).toMatch(/^[1-9]\d{7}$/);
  });

  it('issues nothing once the channel budget is spent, and still issues on the other', async () => {
    for (let i = 0; i < RECOVERY_FAILURE_BUDGET; i += 1) {
      await AuthFailure.create({
        userId: 'user-1',
        type: 'account_recovery_email_failed',
        occurredAt: new Date(),
      });
    }

    expect(await startRecovery('user-1', 'email', 'attempt-1')).toBeNull();
    expect(rows).toHaveLength(0);
    expect(await startRecovery('user-1', 'phone', 'attempt-1')).not.toBeNull();
  });

  it('issues again once the oldest wrong code leaves the window', async () => {
    for (let i = 0; i < RECOVERY_FAILURE_BUDGET; i += 1) {
      await AuthFailure.create({
        userId: 'user-1',
        type: 'account_recovery_email_failed',
        occurredAt: new Date(Date.now() - RECOVERY_FAILURE_WINDOW_MS - 1),
      });
    }

    expect(await startRecovery('user-1', 'email', 'attempt-1')).not.toBeNull();
  });

  it('issues nothing when the budget cannot be read', async () => {
    (AuthFailure.count as any).mockRejectedValueOnce(new Error('db down'));

    expect(await startRecovery('user-1', 'email', 'attempt-1')).toBeNull();
  });

  it('voids an earlier unverified code on the same attempt', async () => {
    await startRecovery('user-1', 'email', 'attempt-1');
    await startRecovery('user-1', 'phone', 'attempt-1');

    expect(rows.map((row) => row.state)).toEqual(['void', 'awaiting_code']);
  });

  it('does not cancel an open request, since anyone who knows the address can start one', async () => {
    await open('attempt-1', 'email');
    await startRecovery('user-1', 'phone', 'attempt-2');

    expect(rows[0].state).toBe('pending');
  });
});

describe('verifyRecovery', () => {
  it('opens the request with the configured delay and a hashed cancel token', async () => {
    const before = Date.now();
    const { request, cancelToken } = await open();

    expect(request.state).toBe('pending');
    expect(request.attemptId).toBe('attempt-1');
    expect(request.codeHash).toBeNull();
    expect(+request.completesAt! - +request.requestedAt!).toBe(HOUR * 1000);
    expect(+request.requestedAt!).toBeGreaterThanOrEqual(before);
    expect(cancelToken.length).toBeGreaterThan(20);
    expect(request.cancelTokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(request.cancelTokenHash).not.toContain(cancelToken);
    expect(recoveryStatus(request).state).toBe('pending');
  });

  it('accepts an email code in any case', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;

    expect((await verifyRecovery('user-1', 'attempt-1', code.toLowerCase(), HOUR)).outcome).toBe(
      'opened',
    );
  });

  it('spends the budget across starts and attempts, and keeps nothing for a right code', async () => {
    const first = (await startRecovery('user-1', 'email', 'attempt-1'))!;
    for (let i = 0; i < MAX_RECOVERY_CODE_ATTEMPTS; i += 1) {
      await verifyRecovery('user-1', 'attempt-1', wrong(first), HOUR);
    }
    const second = (await startRecovery('user-1', 'email', 'attempt-2'))!;
    await verifyRecovery('user-1', 'attempt-2', wrong(second), HOUR);

    expect(failures).toHaveLength(MAX_RECOVERY_CODE_ATTEMPTS + 1);
    expect(failures.every((row) => row.type === 'account_recovery_email_failed')).toBe(true);

    expect((await verifyRecovery('user-1', 'attempt-2', second, HOUR)).outcome).toBe('opened');
    expect(failures).toHaveLength(MAX_RECOVERY_CODE_ATTEMPTS + 1);
  });

  it('refuses the right code once the budget is spent, without spending more', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;
    for (let i = 0; i < RECOVERY_FAILURE_BUDGET; i += 1) {
      await AuthFailure.create({
        userId: 'user-1',
        type: 'account_recovery_email_failed',
        occurredAt: new Date(),
      });
    }

    expect(await verifyRecovery('user-1', 'attempt-1', code, HOUR)).toEqual({
      outcome: 'locked',
    });
    expect(failures).toHaveLength(RECOVERY_FAILURE_BUDGET);
    expect(rows[0]).toMatchObject({ state: 'awaiting_code', failedAttempts: 0 });
  });

  it('refuses the guess when it cannot be recorded', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;
    (AuthFailure.create as any).mockRejectedValueOnce(new Error('db down'));

    expect((await verifyRecovery('user-1', 'attempt-1', code, HOUR)).outcome).toBe('locked');
  });

  it('refuses the guess when the budget cannot be counted', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;
    (AuthFailure.count as any).mockRejectedValueOnce(new Error('db down'));

    expect((await verifyRecovery('user-1', 'attempt-1', code, HOUR)).outcome).toBe('locked');
    expect(failures).toHaveLength(0);
  });

  it('still refuses when a spent guess cannot be released', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;
    for (let i = 0; i < RECOVERY_FAILURE_BUDGET; i += 1) {
      await AuthFailure.create({
        userId: 'user-1',
        type: 'account_recovery_email_failed',
        occurredAt: new Date(),
      });
    }
    (AuthFailure.destroy as any).mockRejectedValueOnce(new Error('db down'));

    expect((await verifyRecovery('user-1', 'attempt-1', code, HOUR)).outcome).toBe('locked');
  });

  it('refuses a code from another attempt', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;

    expect(await verifyRecovery('user-1', 'attempt-2', code, HOUR)).toEqual({
      outcome: 'invalid',
    });
  });

  it(`voids the request after ${MAX_RECOVERY_CODE_ATTEMPTS} wrong codes`, async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;

    for (let i = 0; i < MAX_RECOVERY_CODE_ATTEMPTS; i += 1) {
      expect((await verifyRecovery('user-1', 'attempt-1', wrong(code), HOUR)).outcome).toBe(
        'invalid',
      );
    }

    expect(rows[0].state).toBe('void');
    expect((await verifyRecovery('user-1', 'attempt-1', code, HOUR)).outcome).toBe('invalid');
  });

  it('refuses an expired code and voids it', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;
    rows[0].codeExpiresAt = new Date(Date.now() - 1);

    expect((await verifyRecovery('user-1', 'attempt-1', code, HOUR)).outcome).toBe('invalid');
    expect(rows[0].state).toBe('void');
  });

  it('refuses a try that lost the race to claim it', async () => {
    const code = (await startRecovery('user-1', 'email', 'attempt-1'))!;
    (AccountRecoveryRequest.update as any).mockResolvedValueOnce([0]);

    expect((await verifyRecovery('user-1', 'attempt-1', code, HOUR)).outcome).toBe('invalid');
    expect(rows[0].state).toBe('awaiting_code');
    expect(failures).toHaveLength(0);
  });

  it('leaves an earlier open request alone until the new one is announced', async () => {
    await open('attempt-1', 'email');
    const second = await open('attempt-2', 'phone');

    expect(rows[0].state).toBe('pending');
    expect(second.request.state).toBe('pending');

    expect(await supersedeOtherRecoveries(second.request)).toBe(1);
    expect(rows[0].state).toBe('cancelled');
    expect(rows[1].state).toBe('pending');
  });

  it('voids a request that could not be announced, leaving earlier ones open', async () => {
    await open('attempt-1', 'email');
    const second = await open('attempt-2', 'phone');

    await voidUnannouncedRecovery(second.request);

    expect(rows[0].state).toBe('pending');
    expect(rows[1]).toMatchObject({ state: 'void', cancelTokenHash: null });
  });

  it('resumes an open request on a new attempt through the same channel, keeping its clock', async () => {
    const { request } = await open('attempt-1', 'email');
    const completesAt = request.completesAt;
    const code = (await startRecovery('user-1', 'email', 'attempt-2'))!;

    const result = await verifyRecovery('user-1', 'attempt-2', code, HOUR * 48);

    expect(result.outcome).toBe('resumed');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ state: 'pending', attemptId: 'attempt-2', completesAt });
  });

  it('leaves an open request intact when a resume code is guessed wrong too often', async () => {
    await open('attempt-1', 'email');
    const code = (await startRecovery('user-1', 'email', 'attempt-2'))!;

    for (let i = 0; i < MAX_RECOVERY_CODE_ATTEMPTS; i += 1) {
      await verifyRecovery('user-1', 'attempt-2', wrong(code), HOUR);
    }

    expect(rows[0]).toMatchObject({ state: 'pending', attemptId: 'attempt-1', codeHash: null });
  });
});

describe('completeRecovery', () => {
  it('refuses before the delay has passed', async () => {
    await open();

    const result = await completeRecovery('user-1', 'attempt-1');

    expect(result.outcome).toBe('not_ready');
    expect(rows[0].state).toBe('pending');
    expect(Session.update).not.toHaveBeenCalled();
  });

  it('completes a ready request and revokes every session', async () => {
    await open();
    vi.useFakeTimers({ now: Date.now() + HOUR * 1000 + 1, toFake: ['Date'] });

    const result = await completeRecovery('user-1', 'attempt-1');

    expect(result).toMatchObject({ outcome: 'completed', revokedSessions: 3 });
    expect(rows[0].state).toBe('completed');
    expect(Session.update).toHaveBeenCalledWith(
      expect.objectContaining({ revokedReason: 'account_recovery' }),
      { where: { userId: 'user-1', revokedAt: null } },
    );
    // The cutoff, so a refresh that raced completion cannot keep a session alive.
    expect(User.update).toHaveBeenCalledWith(
      { sessionsRevokedBefore: expect.any(Date) },
      { where: { id: 'user-1' } },
    );
    expect(recoveryStatus(rows[0] as any).state).toBe('completed');
    expect((await completeRecovery('user-1', 'attempt-1')).outcome).toBe('not_found');
  });

  it('finds nothing for an attempt that opened no request', async () => {
    await open();

    expect((await completeRecovery('user-1', 'attempt-2')).outcome).toBe('not_found');
    expect(await findRecoveryForAttempt('user-1', 'attempt-2')).toBeNull();
  });

  it('refuses when another request completed it first', async () => {
    await open();
    vi.useFakeTimers({ now: Date.now() + HOUR * 1000 + 1, toFake: ['Date'] });
    (AccountRecoveryRequest.update as any).mockResolvedValueOnce([0]);

    expect((await completeRecovery('user-1', 'attempt-1')).outcome).toBe('not_found');
    expect(Session.update).not.toHaveBeenCalled();
  });
});

describe('cancelRecoveryByToken', () => {
  it('cancels the open request the token belongs to', async () => {
    const { cancelToken } = await open();

    const cancelled = await cancelRecoveryByToken(cancelToken);

    expect(cancelled?.userId).toBe('user-1');
    expect(rows[0].state).toBe('cancelled');
    expect(recoveryStatus(rows[0] as any).state).toBe('cancelled');
  });

  it('matches nothing for an unknown token or a request already closed', async () => {
    const { cancelToken } = await open();

    expect(await cancelRecoveryByToken('not-a-token')).toBeNull();
    await cancelRecoveryByToken(cancelToken);
    expect(await cancelRecoveryByToken(cancelToken)).toBeNull();
  });

  it('matches nothing when another request cancelled it first', async () => {
    const { cancelToken } = await open();
    (AccountRecoveryRequest.update as any).mockResolvedValueOnce([0]);

    expect(await cancelRecoveryByToken(cancelToken)).toBeNull();
  });
});
