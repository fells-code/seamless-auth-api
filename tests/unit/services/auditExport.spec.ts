import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSequelize } from '../../../src/models/index.js';
import { AUDIT_EXPORT_FORMAT, streamAuthEventExport } from '../../../src/services/auditExport.js';

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: vi.fn(),
}));

const query = vi.fn();

function row(seq: number) {
  return {
    seq: String(seq),
    id: `event-${seq}`,
    created_at: new Date(`2026-01-0${seq}T00:00:00Z`),
    type: 'login_success',
    user_id: 'user-1',
    actor_user_id: null,
    session_id: null,
    attempt_id: null,
    ip_address: '10.0.0.1',
    user_agent: 'agent',
    deployment_id: 'app',
    device_class: 'desktop',
    mail_provider: null,
    owner: false,
    metadata: { n: seq },
    prev_hash:
      seq === 1
        ? 'a'.repeat(64)
        : String(seq - 1)
            .repeat(64)
            .slice(0, 64),
    hash: String(seq).repeat(64).slice(0, 64),
    payload: `[${seq}]`,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getSequelize).mockReturnValue({ query } as never);
});

describe('streamAuthEventExport', () => {
  it('writes every event in chain order and ends with a manifest', async () => {
    query
      .mockResolvedValueOnce([{ first_seq: '1', last_seq: '3' }])
      .mockResolvedValueOnce([row(1), row(2), row(3)])
      .mockResolvedValueOnce([]);
    const lines: string[] = [];

    const manifest = await streamAuthEventExport({
      from: new Date('2026-01-01T00:00:00Z'),
      to: new Date('2026-02-01T00:00:00Z'),
      write: (line) => {
        lines.push(line);
      },
    });

    const parsed = lines.map((line) => JSON.parse(line));
    expect(parsed.slice(0, 3).map((event) => event.seq)).toEqual([1, 2, 3]);
    expect(parsed[0]).toEqual(
      expect.objectContaining({
        id: 'event-1',
        createdAt: '2026-01-01T00:00:00.000Z',
        prevHash: 'a'.repeat(64),
        payload: '[1]',
      }),
    );
    expect(parsed[3]).toEqual(manifest);
    expect(manifest).toEqual(
      expect.objectContaining({
        type: 'manifest',
        format: AUDIT_EXPORT_FORMAT,
        reason: 'export',
        from: '2026-01-01T00:00:00.000Z',
        to: '2026-02-01T00:00:00.000Z',
        firstSeq: 1,
        lastSeq: 3,
        count: 3,
        anchorHash: 'a'.repeat(64),
        lastHash: row(3).hash,
      }),
    );
  });

  it('reads a contiguous seq range from the pinned bounds, not a created_at filter', async () => {
    query.mockResolvedValueOnce([{ first_seq: '5', last_seq: '9' }]).mockResolvedValueOnce([]);

    await streamAuthEventExport({ write: () => undefined });

    const [batchSql, batchOptions] = query.mock.calls[1];
    expect(batchSql).toContain('e.seq > :afterSeq AND e.seq <= :maxSeq');
    expect(batchSql).not.toContain('created_at >=');
    expect(batchOptions.replacements).toEqual(expect.objectContaining({ afterSeq: 4, maxSeq: 9 }));
  });

  it('writes only a manifest for an empty period', async () => {
    query.mockResolvedValueOnce([{ first_seq: null, last_seq: null }]);
    const lines: string[] = [];

    const manifest = await streamAuthEventExport({ write: (line) => void lines.push(line) });

    expect(lines).toHaveLength(1);
    expect(manifest).toEqual(
      expect.objectContaining({ count: 0, firstSeq: null, lastSeq: null, anchorHash: null }),
    );
    expect(query).toHaveBeenCalledTimes(1);
  });
});
