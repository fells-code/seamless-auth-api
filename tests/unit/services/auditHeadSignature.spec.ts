import { beforeEach, describe, expect, it, vi } from 'vitest';

const query = vi.fn();
const error = vi.fn();

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: () => ({ query }),
}));

vi.mock('../../../src/utils/logger.js', () => ({
  default: () => ({ error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() }),
}));

const KEY = 'unit-audit-key';
const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const tx = { id: 'tx' } as never;

async function load() {
  return import('../../../src/services/auditHeadSignature.js');
}

beforeEach(() => {
  vi.resetModules();
});

describe('auditChainKey', () => {
  it('reads a trimmed key and treats a blank one as unset', async () => {
    const { auditChainKey } = await load();

    expect(auditChainKey({ AUDIT_CHAIN_KEY: ' k ' })).toBe('k');
    expect(auditChainKey({ AUDIT_CHAIN_KEY: '  ' })).toBeNull();
    expect(auditChainKey({})).toBeNull();
  });
});

describe('auditHeadSignatureValid', () => {
  it('accepts its own signature and nothing else', async () => {
    const { auditHeadSignatureValid, signAuditHead } = await load();
    const signature = signAuditHead(KEY, 4, A);

    expect(auditHeadSignatureValid(KEY, 4, A, signature)).toBe(true);
    expect(auditHeadSignatureValid(KEY, 5, A, signature)).toBe(false);
    expect(auditHeadSignatureValid(KEY, 4, B, signature)).toBe(false);
    expect(auditHeadSignatureValid('other', 4, A, signature)).toBe(false);
    expect(auditHeadSignatureValid(KEY, 4, A, null)).toBe(false);
    expect(auditHeadSignatureValid(KEY, 4, A, 'zz')).toBe(false);
  });

  it('signs an empty head distinctly from any row', async () => {
    const { signAuditHead } = await load();

    expect(signAuditHead(KEY, 0, null)).not.toBe(signAuditHead(KEY, 0, A));
  });
});

describe('signInsertedAuditHead', () => {
  it('moves the signature forward from the previous head in one statement', async () => {
    const { signAuditHead, signInsertedAuditHead } = await load();
    query.mockResolvedValueOnce([{ signed_seq: '5' }]);

    await expect(signInsertedAuditHead({ seq: '5', hash: B, prev_hash: A }, tx, KEY)).resolves.toBe(
      true,
    );

    expect(query).toHaveBeenCalledTimes(1);
    expect(query.mock.calls[0][1]).toMatchObject({
      replacements: {
        seq: 5,
        signature: signAuditHead(KEY, 5, B),
        prevSeq: 4,
        prevSignature: signAuditHead(KEY, 4, A),
      },
      transaction: tx,
    });
  });

  it('catches up from an older signature that still verifies', async () => {
    const { signAuditHead, signInsertedAuditHead } = await load();
    query
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([
        { signed_seq: '3', signature: signAuditHead(KEY, 3, A), signed_hash: A },
      ])
      .mockResolvedValueOnce([]);

    await expect(
      signInsertedAuditHead({ seq: 5, hash: B, prev_hash: 'c'.repeat(64) }, tx, KEY),
    ).resolves.toBe(true);

    expect(query.mock.calls[2][1]).toMatchObject({
      replacements: { seq: 5, signature: signAuditHead(KEY, 5, B), signedSeq: 3 },
    });
    expect(error).not.toHaveBeenCalled();
  });

  it.each([
    ['unsigned', { signed_seq: null, signature: null, signed_hash: null }],
    ['signed with another key', { signed_seq: '3', signature: 'f'.repeat(64), signed_hash: A }],
    ['signed ahead of the insert', { signed_seq: '9', signature: 'f'.repeat(64), signed_hash: A }],
  ])('leaves a head that is %s alone and says so once', async (_case, current) => {
    const { signInsertedAuditHead } = await load();
    query.mockResolvedValue([]);
    query.mockResolvedValueOnce([]).mockResolvedValueOnce([current]);

    await expect(signInsertedAuditHead({ seq: 5, hash: B, prev_hash: A }, tx, KEY)).resolves.toBe(
      false,
    );
    await signInsertedAuditHead({ seq: 6, hash: A, prev_hash: B }, tx, KEY);

    expect(query).toHaveBeenCalledTimes(4);
    expect(error).toHaveBeenCalledTimes(1);
    error.mockClear();
  });

  it('does nothing for a row the database did not chain', async () => {
    const { signInsertedAuditHead } = await load();

    await expect(signInsertedAuditHead({ seq: null, hash: B }, tx, KEY)).resolves.toBe(false);
    await expect(signInsertedAuditHead({ seq: 1, hash: null }, tx, KEY)).resolves.toBe(false);
    expect(query).not.toHaveBeenCalled();
  });
});

describe('warnIfAuditChainKeyUnset', () => {
  it('warns only in production without the key', async () => {
    const warn = vi.fn();
    vi.doMock('../../../src/utils/logger.js', () => ({
      default: () => ({ error, warn, info: vi.fn(), debug: vi.fn() }),
    }));
    const { warnIfAuditChainKeyUnset } = await load();

    warnIfAuditChainKeyUnset({ NODE_ENV: 'development' });
    warnIfAuditChainKeyUnset({ NODE_ENV: 'production', AUDIT_CHAIN_KEY: 'k' });
    expect(warn).not.toHaveBeenCalled();

    warnIfAuditChainKeyUnset({ NODE_ENV: 'production' });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('AUDIT_CHAIN_KEY is not set'));
  });
});
