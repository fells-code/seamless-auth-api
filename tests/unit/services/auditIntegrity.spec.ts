import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import { signAuditHead } from '../../../src/services/auditHeadSignature.js';
import {
  AuditHeadSealError,
  sealAuditChainHead,
  verifyAuthEventChain,
} from '../../../src/services/auditIntegrity.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

const query = vi.fn();
const transaction = vi.fn();
const KEY = 'unit-audit-key';
const C = 'c'.repeat(64);

function chainRow(overrides: Record<string, unknown> = {}) {
  return {
    rows_checked: '3',
    first_seq: '1',
    last_seq: '3',
    last_hash: 'c'.repeat(64),
    anchor_hash: null,
    first_failure: null,
    head: { seq: '3', hash: 'c'.repeat(64) },
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getSequelize).mockReturnValue({ query, transaction } as never);
  transaction.mockImplementation((fn: (tx: unknown) => unknown) => fn({ id: 'tx' }));
});

describe('verifyAuthEventChain', () => {
  it('reports an intact chain', async () => {
    query.mockResolvedValue([chainRow()]);

    const report = await verifyAuthEventChain();

    expect(report).toEqual(
      expect.objectContaining({
        verified: true,
        rowsChecked: 3,
        firstSeq: 1,
        lastSeq: 3,
        anchorHash: null,
        head: { seq: 3, hash: 'c'.repeat(64) },
        firstFailure: null,
      }),
    );
  });

  it('recomputes hashes with the same database functions the insert trigger uses', async () => {
    query.mockResolvedValue([chainRow()]);

    await verifyAuthEventChain();

    const sql = query.mock.calls[0][0] as string;
    expect(sql).toContain('public.auth_event_hash(e.prev_hash, public.auth_event_payload(e.*))');
  });

  it('passes through the first broken row', async () => {
    query.mockResolvedValue([
      chainRow({ first_failure: { seq: '2', id: 'event-2', reason: 'hash_mismatch' } }),
    ]);

    const report = await verifyAuthEventChain();

    expect(report.verified).toBe(false);
    expect(report.firstFailure).toEqual({ seq: 2, id: 'event-2', reason: 'hash_mismatch' });
  });

  it('reports rows missing from the end as a head mismatch', async () => {
    query.mockResolvedValue([
      chainRow({
        last_seq: '2',
        last_hash: 'b'.repeat(64),
        head: { seq: '3', hash: 'c'.repeat(64) },
      }),
    ]);

    const report = await verifyAuthEventChain();

    expect(report.verified).toBe(false);
    expect(report.firstFailure).toEqual({ seq: 3, id: null, reason: 'head_mismatch' });
  });

  it('accepts an empty trail whose head has never moved', async () => {
    query.mockResolvedValue([
      chainRow({
        rows_checked: '0',
        first_seq: null,
        last_seq: null,
        last_hash: null,
        head: { seq: '0', hash: null },
      }),
    ]);

    expect((await verifyAuthEventChain()).verified).toBe(true);
  });

  it('refuses an empty trail whose head says events were written', async () => {
    query.mockResolvedValue([
      chainRow({
        rows_checked: '0',
        first_seq: null,
        last_seq: null,
        last_hash: null,
        head: { seq: '5', hash: 'e'.repeat(64) },
      }),
    ]);

    const report = await verifyAuthEventChain();

    expect(report.verified).toBe(false);
    expect(report.firstFailure?.reason).toBe('head_mismatch');
  });
});

function signedHead(overrides: Record<string, unknown> = {}) {
  return {
    seq: '3',
    hash: C,
    signed_seq: '3',
    signature: signAuditHead(KEY, 3, C),
    signed_hash: C,
    ...overrides,
  };
}

describe('verifyAuthEventChain with AUDIT_CHAIN_KEY', () => {
  beforeEach(() => {
    vi.stubEnv('AUDIT_CHAIN_KEY', KEY);
  });

  it('verifies a head signed with the key', async () => {
    query.mockResolvedValue([chainRow({ head: signedHead() })]);

    expect(await verifyAuthEventChain()).toMatchObject({
      verified: true,
      headSigned: true,
      head: { seq: 3, hash: C },
    });
  });

  it('reports an unsigned head', async () => {
    query.mockResolvedValue([
      chainRow({ head: signedHead({ signed_seq: null, signature: null, signed_hash: null }) }),
    ]);

    expect(await verifyAuthEventChain()).toMatchObject({
      verified: false,
      headSigned: false,
      firstFailure: { seq: 3, id: null, reason: 'head_unsigned' },
    });
  });

  it('reports a signature that lags the head as unsigned', async () => {
    const B = 'b'.repeat(64);
    query.mockResolvedValue([
      chainRow({
        head: signedHead({ signed_seq: '2', signature: signAuditHead(KEY, 2, B), signed_hash: B }),
      }),
    ]);

    expect((await verifyAuthEventChain()).firstFailure?.reason).toBe('head_unsigned');
  });

  it('reports a signature that does not verify as a head mismatch', async () => {
    query.mockResolvedValue([
      chainRow({ head: signedHead({ signature: signAuditHead('another-key', 3, C) }) }),
    ]);

    expect(await verifyAuthEventChain()).toMatchObject({
      verified: false,
      headSigned: false,
      firstFailure: { seq: 3, id: null, reason: 'head_mismatch' },
    });
  });

  it('reports a signature over a row that is gone as a head mismatch', async () => {
    query.mockResolvedValue([chainRow({ head: signedHead({ signed_hash: null }) })]);

    expect((await verifyAuthEventChain()).firstFailure?.reason).toBe('head_mismatch');
  });

  it('reports a broken row ahead of the signature', async () => {
    query.mockResolvedValue([
      chainRow({
        head: signedHead({ signature: null }),
        first_failure: { seq: '2', id: 'event-2', reason: 'hash_mismatch' },
      }),
    ]);

    expect((await verifyAuthEventChain()).firstFailure?.reason).toBe('hash_mismatch');
  });

  it('does not check signatures without the key', async () => {
    vi.stubEnv('AUDIT_CHAIN_KEY', '');
    query.mockResolvedValue([chainRow({ head: signedHead({ signature: null }) })]);

    expect(await verifyAuthEventChain()).toMatchObject({ verified: true, headSigned: false });
  });
});

describe('sealAuditChainHead', () => {
  it('refuses without the key', async () => {
    vi.stubEnv('AUDIT_CHAIN_KEY', '');

    await expect(sealAuditChainHead()).rejects.toBeInstanceOf(AuditHeadSealError);
    expect(transaction).not.toHaveBeenCalled();
  });

  it('locks the head, checks the chain and signs the head', async () => {
    vi.stubEnv('AUDIT_CHAIN_KEY', KEY);
    query
      .mockResolvedValueOnce([{ id: 1 }])
      .mockResolvedValueOnce([chainRow({ head: signedHead({ signature: null }) })])
      .mockResolvedValueOnce([]);

    await expect(sealAuditChainHead()).resolves.toEqual({ seq: 3, hash: C });

    expect(query.mock.calls[0][0]).toContain('FOR UPDATE');
    expect(query.mock.calls[1][1]).toMatchObject({ transaction: { id: 'tx' } });
    expect(query.mock.calls[2][1]).toMatchObject({
      replacements: { seq: 3, signature: signAuditHead(KEY, 3, C) },
      transaction: { id: 'tx' },
    });
  });

  it('refuses a chain that does not verify', async () => {
    vi.stubEnv('AUDIT_CHAIN_KEY', KEY);
    query
      .mockResolvedValueOnce([{ id: 1 }])
      .mockResolvedValueOnce([chainRow({ last_seq: '2', last_hash: 'b'.repeat(64) })]);

    await expect(sealAuditChainHead()).rejects.toThrow(/head_mismatch at seq 3/);
    expect(query).toHaveBeenCalledTimes(2);
  });

  it('refuses when the head row is missing', async () => {
    vi.stubEnv('AUDIT_CHAIN_KEY', KEY);
    query.mockResolvedValueOnce([]).mockResolvedValueOnce([chainRow({ head: null })]);

    await expect(sealAuditChainHead()).rejects.toThrow(/head row is missing/);
  });
});
