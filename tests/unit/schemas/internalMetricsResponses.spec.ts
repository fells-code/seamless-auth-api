import { describe, expect, it } from 'vitest';

import { SecurityAnomaliesResponseSchema } from '../../../src/schemas/internalMetrics.responses.js';

describe('SecurityAnomaliesResponseSchema', () => {
  it('coerces and serializes event timestamps to ISO strings', () => {
    const parsed = SecurityAnomaliesResponseSchema.safeParse({
      suspiciousEvents: [
        {
          type: 'login_failed',
          created_at: '2026-01-01T00:00:00.000Z',
          updated_at: new Date('2026-02-02T12:00:00.000Z'),
        },
      ],
      total: 1,
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.suspiciousEvents[0].created_at).toBe('2026-01-01T00:00:00.000Z');
      expect(parsed.data.suspiciousEvents[0].updated_at).toBe('2026-02-02T12:00:00.000Z');
    }
  });

  it('rejects a negative total', () => {
    const parsed = SecurityAnomaliesResponseSchema.safeParse({
      suspiciousEvents: [],
      total: -1,
    });

    expect(parsed.success).toBe(false);
  });
});
