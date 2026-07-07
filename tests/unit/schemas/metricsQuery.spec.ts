import { describe, expect, it } from 'vitest';

import { MetricsQuerySchema } from '../../../src/schemas/internal.query.js';

describe('MetricsQuerySchema', () => {
  it('accepts a valid range and defaults interval to hour', () => {
    const parsed = MetricsQuerySchema.safeParse({
      from: '2026-01-01T00:00:00.000Z',
      to: '2026-01-08T00:00:00.000Z',
    });

    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.interval).toBe('hour');
  });

  it('accepts an empty query', () => {
    expect(MetricsQuerySchema.safeParse({}).success).toBe(true);
  });

  it('rejects an unparseable from date', () => {
    const parsed = MetricsQuerySchema.safeParse({ from: 'not-a-date' });

    expect(parsed.success).toBe(false);
  });

  it('rejects an inverted range (from after to)', () => {
    const parsed = MetricsQuerySchema.safeParse({
      from: '2026-02-01T00:00:00.000Z',
      to: '2026-01-01T00:00:00.000Z',
    });

    expect(parsed.success).toBe(false);
  });

  it('rejects a window larger than the maximum', () => {
    const parsed = MetricsQuerySchema.safeParse({
      from: '2020-01-01T00:00:00.000Z',
      to: '2026-01-01T00:00:00.000Z',
    });

    expect(parsed.success).toBe(false);
  });
});
