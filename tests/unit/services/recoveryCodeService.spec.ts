import { beforeEach, describe, expect, it } from 'vitest';

import { RecoveryCode } from '../../../src/models/recoveryCodes.js';
import {
  generateRecoveryCodes,
  getRecoveryCodeStatus,
  normalizeRecoveryCode,
  RECOVERY_CODE_COUNT,
  redeemRecoveryCode,
} from '../../../src/services/recoveryCodeService.js';

beforeEach(() => {
  process.env.REFRESH_TOKEN_LOOKUP_SECRET = 'lookup-secret';
});

describe('generateRecoveryCodes', () => {
  it('returns ten base32 codes shown as XXXXX-XXXXX and stores only their hashes', async () => {
    const { codes } = await generateRecoveryCodes('user-1');

    expect(codes).toHaveLength(RECOVERY_CODE_COUNT);
    expect(new Set(codes).size).toBe(RECOVERY_CODE_COUNT);
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    }

    expect(RecoveryCode.destroy).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'user-1' } }),
    );
    const stored = (RecoveryCode.bulkCreate as any).mock.calls[0][0] as Array<{ codeHash: string }>;
    expect(stored).toHaveLength(RECOVERY_CODE_COUNT);
    for (const row of stored) {
      expect(row.codeHash).toMatch(/^[0-9a-f]{64}$/);
      expect(codes.some((code) => row.codeHash.includes(normalizeRecoveryCode(code)))).toBe(false);
    }
  });

  it('keys the hash, so the same code hashes differently under another secret', async () => {
    const hashUnder = async (secret: string) => {
      process.env.REFRESH_TOKEN_LOOKUP_SECRET = secret;
      await redeemRecoveryCode('user-1', 'ABCDE-FGH23');
      return (RecoveryCode.update as any).mock.calls.at(-1)[1].where.codeHash;
    };

    expect(await hashUnder('one-secret')).not.toBe(await hashUnder('another-secret'));
    expect(await hashUnder('one-secret')).toBe(await hashUnder('one-secret'));
  });
});

describe('redeemRecoveryCode', () => {
  it('spends an unused code with one conditional update, whatever its case or dash', async () => {
    await redeemRecoveryCode('user-1', 'abcde-fgh23');
    const lower = (RecoveryCode.update as any).mock.calls.at(-1);
    await redeemRecoveryCode('user-1', 'ABCDEFGH23');
    const upper = (RecoveryCode.update as any).mock.calls.at(-1);

    expect(lower[0]).toEqual({ usedAt: expect.any(Date) });
    expect(lower[1].where).toEqual({
      userId: 'user-1',
      codeHash: expect.any(String),
      usedAt: null,
    });
    expect(lower[1].where.codeHash).toBe(upper[1].where.codeHash);
  });

  it('fails when no unused code matched', async () => {
    (RecoveryCode.update as any).mockResolvedValueOnce([0]);

    expect(await redeemRecoveryCode('user-1', 'ABCDE-FGH23')).toBe(false);
  });
});

describe('getRecoveryCodeStatus', () => {
  it('counts the unused codes and dates the set', async () => {
    const createdAt = new Date('2026-10-22T00:00:00Z');
    (RecoveryCode.findAll as any).mockResolvedValueOnce([
      { usedAt: null, createdAt },
      { usedAt: new Date(), createdAt },
    ]);

    expect(await getRecoveryCodeStatus('user-1')).toEqual({ remaining: 1, total: 2, createdAt });
  });

  it('has no date before a set exists', async () => {
    expect(await getRecoveryCodeStatus('user-1')).toEqual({
      remaining: 0,
      total: 0,
      createdAt: null,
    });
  });
});
