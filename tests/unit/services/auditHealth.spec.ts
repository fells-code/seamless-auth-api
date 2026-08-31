import { beforeEach, describe, expect, it } from 'vitest';

import {
  AUDIT_DEGRADED_WINDOW_MS,
  getAuditHealth,
  recordAuditWriteFailure,
  resetAuditHealthForTests,
} from '../../../src/services/auditHealth.js';

const NOW = new Date('2026-08-31T12:00:00.000Z');

beforeEach(() => {
  resetAuditHealthForTests();
});

describe('auditHealth', () => {
  it('is healthy before anything has failed', () => {
    expect(getAuditHealth(NOW)).toEqual({
      degraded: false,
      failureCount: 0,
      lastFailureAt: null,
    });
  });

  it('reports degraded after a write failure', () => {
    recordAuditWriteFailure(new Error('disk full'), NOW);

    expect(getAuditHealth(NOW)).toEqual({
      degraded: true,
      failureCount: 1,
      lastFailureAt: NOW.toISOString(),
    });
  });

  it('counts repeated failures', () => {
    recordAuditWriteFailure(new Error('one'), NOW);
    recordAuditWriteFailure(new Error('two'), NOW);

    expect(getAuditHealth(NOW).failureCount).toBe(2);
  });

  // An instance that recovers should stop claiming to be degraded on its own,
  // rather than needing a restart to clear the flag.
  it('recovers once the window has passed', () => {
    recordAuditWriteFailure(new Error('transient'), NOW);

    const afterWindow = new Date(NOW.getTime() + AUDIT_DEGRADED_WINDOW_MS + 1);

    expect(getAuditHealth(afterWindow).degraded).toBe(false);
    // The total is still visible, so a recovered instance does not hide that it
    // lost events.
    expect(getAuditHealth(afterWindow).failureCount).toBe(1);
  });

  it('stays degraded inside the window', () => {
    recordAuditWriteFailure(new Error('transient'), NOW);

    const insideWindow = new Date(NOW.getTime() + AUDIT_DEGRADED_WINDOW_MS - 1);

    expect(getAuditHealth(insideWindow).degraded).toBe(true);
  });
});
