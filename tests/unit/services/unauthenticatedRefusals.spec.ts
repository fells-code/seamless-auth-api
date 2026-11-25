import { beforeEach, describe, expect, it, vi } from 'vitest';

const warn = vi.fn();

vi.mock('../../../src/utils/logger.js', () => ({
  default: () => ({ warn, error: vi.fn(), info: vi.fn(), debug: vi.fn() }),
}));

const {
  REFUSAL_SUMMARY_INTERVAL_MS,
  countUnauthenticatedRefusal,
  getUnauthenticatedRefusalCounts,
  resetUnauthenticatedRefusalsForTests,
} = await import('../../../src/services/unauthenticatedRefusals.js');

beforeEach(() => {
  resetUnauthenticatedRefusalsForTests(0);
});

describe('countUnauthenticatedRefusal', () => {
  it('counts each kind without logging inside the window', () => {
    countUnauthenticatedRefusal('unknown_route', 10);
    countUnauthenticatedRefusal('unknown_route', 20);
    countUnauthenticatedRefusal('refresh_token_missing', 30);

    expect(getUnauthenticatedRefusalCounts()).toEqual({
      unknown_route: 2,
      refresh_token_missing: 1,
    });
    expect(warn).not.toHaveBeenCalled();
  });

  it('logs one summary per window and starts counting again', () => {
    countUnauthenticatedRefusal('cors_origin_refused', 10);
    countUnauthenticatedRefusal('refresh_token_unknown', REFUSAL_SUMMARY_INTERVAL_MS);

    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      'Unauthenticated refusals in the last 60s: cors_origin_refused=1 refresh_token_unknown=1',
    );
    expect(getUnauthenticatedRefusalCounts()).toEqual({});

    countUnauthenticatedRefusal('unknown_route', REFUSAL_SUMMARY_INTERVAL_MS + 1);

    expect(getUnauthenticatedRefusalCounts()).toEqual({ unknown_route: 1 });
    expect(warn).toHaveBeenCalledTimes(1);
  });
});
