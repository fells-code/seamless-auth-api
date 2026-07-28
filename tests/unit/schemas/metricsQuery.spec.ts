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

  it('rejects an unparseable to date', () => {
    const parsed = MetricsQuerySchema.safeParse({
      from: '2026-01-01T00:00:00.000Z',
      to: 'not-a-date',
    });

    expect(parsed.success).toBe(false);
    expect(parsed.success === false && parsed.error.issues[0].message).toBe('Invalid to date');
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

  it('caps the window by the requested bucket size', () => {
    const range = { from: '2026-01-01T00:00:00.000Z', to: '2026-04-01T00:00:00.000Z' };

    expect(MetricsQuerySchema.safeParse({ ...range, interval: 'hour' }).success).toBe(false);
    expect(MetricsQuerySchema.safeParse({ ...range, interval: 'day' }).success).toBe(true);
  });

  it('measures an open-ended window against now', () => {
    const recent = new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString();
    const ancient = new Date(Date.now() - 1000 * 60 * 60 * 24 * 400).toISOString();

    expect(MetricsQuerySchema.safeParse({ from: recent }).success).toBe(true);
    expect(MetricsQuerySchema.safeParse({ from: ancient, interval: 'day' }).success).toBe(false);
  });

  it('rejects a from date in the future when to is omitted', () => {
    const future = new Date(Date.now() + 1000 * 60 * 60).toISOString();

    expect(MetricsQuerySchema.safeParse({ from: future }).success).toBe(false);
  });
});
