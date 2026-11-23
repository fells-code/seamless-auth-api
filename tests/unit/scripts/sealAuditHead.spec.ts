import { beforeEach, describe, expect, it, vi } from 'vitest';

const close = vi.fn();
const initializeModels = vi.fn();
const sealAuditChainHead = vi.fn();

vi.mock('../../../src/models/index.js', () => ({
  getSequelize: () => ({ close }),
  initializeModels,
}));

vi.mock('../../../src/services/auditIntegrity.js', () => ({ sealAuditChainHead }));

beforeEach(() => {
  vi.resetModules();
  process.exitCode = undefined;
  close.mockResolvedValue(undefined);
});

describe('sealAuditHead script', () => {
  it('signs the head and closes the connection', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    sealAuditChainHead.mockResolvedValue({ seq: 7, hash: 'a'.repeat(64) });

    await import('../../../src/scripts/sealAuditHead.js');

    expect(log).toHaveBeenCalledWith(expect.stringContaining('seq 7'));
    expect(close).toHaveBeenCalled();
    expect(process.exitCode).toBeUndefined();
  });

  it('exits non-zero when the head cannot be signed', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    sealAuditChainHead.mockRejectedValue(new Error('does not verify'));
    close.mockRejectedValue(new Error('already closed'));

    await import('../../../src/scripts/sealAuditHead.js');

    expect(err).toHaveBeenCalledWith(expect.stringContaining('does not verify'));
    expect(process.exitCode).toBe(1);
    process.exitCode = undefined;
  });
});
