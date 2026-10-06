import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import { verifyAuthEventChain } from '../../../src/services/auditIntegrity.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

const query = vi.fn();

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
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
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
