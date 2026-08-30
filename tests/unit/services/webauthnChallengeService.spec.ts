import { beforeEach, describe, expect, it, vi } from 'vitest';

import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges';
import {
  CHALLENGE_TTL_SECONDS,
  consumeChallenge,
  invalidateChallengesForUser,
  issueChallenge,
} from '../../../src/services/webauthnChallengeService';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory';

const NOW = new Date('2026-01-01T00:00:00.000Z');

beforeEach(() => {
  vi.clearAllMocks();
});

describe('issueChallenge', () => {
  it('stores the challenge against one user and one flow, with a bounded life', async () => {
    (WebAuthnChallenge.create as any).mockResolvedValue({});

    await issueChallenge({
      userId: 'user-1',
      purpose: 'registration',
      challenge: 'abc',
      now: NOW,
    });

    expect(WebAuthnChallenge.create).toHaveBeenCalledWith({
      userId: 'user-1',
      purpose: 'registration',
      challenge: 'abc',
      context: null,
      expiresAt: new Date(NOW.getTime() + CHALLENGE_TTL_SECONDS * 1000),
    });
  });

  it('spends anything still outstanding for the same flow', async () => {
    (WebAuthnChallenge.create as any).mockResolvedValue({});

    await issueChallenge({ userId: 'user-1', purpose: 'step_up', challenge: 'abc', now: NOW });

    expect(WebAuthnChallenge.update).toHaveBeenCalledWith(
      { consumedAt: NOW },
      { where: { userId: 'user-1', purpose: 'step_up', consumedAt: null } },
    );
  });

  it('leaves a different flow alone, so registration and login can overlap', async () => {
    (WebAuthnChallenge.create as any).mockResolvedValue({});

    await issueChallenge({
      userId: 'user-1',
      purpose: 'registration',
      challenge: 'abc',
      now: NOW,
    });

    const [, options] = (WebAuthnChallenge.update as any).mock.calls[0];

    expect(options.where.purpose).toBe('registration');
  });
});

describe('consumeChallenge', () => {
  it('only looks at unspent challenges that have not expired', async () => {
    (WebAuthnChallenge.findOne as any).mockResolvedValue(buildWebAuthnChallenge());

    await consumeChallenge({ userId: 'user-1', purpose: 'authentication', now: NOW });

    const [options] = (WebAuthnChallenge.findOne as any).mock.calls[0];

    expect(options.where.consumedAt).toBeNull();
    expect(options.where.expiresAt).toBeDefined();
    expect(options.order).toEqual([['createdAt', 'DESC']]);
  });

  it('spends the challenge as it hands it back', async () => {
    const record = buildWebAuthnChallenge({ challenge: 'abc' });
    (WebAuthnChallenge.findOne as any).mockResolvedValue(record);

    const result = await consumeChallenge({
      userId: 'user-1',
      purpose: 'authentication',
      now: NOW,
    });

    expect(result).toEqual({ challenge: 'abc', context: null });
    expect(record.update).toHaveBeenCalledWith({ consumedAt: NOW });
  });

  it('returns nothing when no live challenge exists', async () => {
    (WebAuthnChallenge.findOne as any).mockResolvedValue(null);

    expect(
      await consumeChallenge({ userId: 'user-1', purpose: 'authentication', now: NOW }),
    ).toBeNull();
  });

  it('carries the flow context back with the challenge', async () => {
    (WebAuthnChallenge.findOne as any).mockResolvedValue(
      buildWebAuthnChallenge({ context: { requirePrf: true } }),
    );

    const result = await consumeChallenge({
      userId: 'user-1',
      purpose: 'registration',
      now: NOW,
    });

    expect(result?.context).toEqual({ requirePrf: true });
  });
});

describe('invalidateChallengesForUser', () => {
  it('spends every outstanding challenge across all flows', async () => {
    await invalidateChallengesForUser('user-1', NOW);

    expect(WebAuthnChallenge.update).toHaveBeenCalledWith(
      { consumedAt: NOW },
      { where: { userId: 'user-1', consumedAt: null } },
    );
  });
});
