import { vi, describe, expect, it } from 'vitest';

vi.unmock('../../../src/utils/utils');

import {
  isValidEmail,
  isValidPhoneNumber,
  computeRotatedSessionTimes,
  computeSessionTimes,
  normalizePhoneNumber,
  parseDurationToSeconds,
  hashSha256,
  hashDeviceFingerprint,
} from '../../../src/utils/utils';
import { SYSTEM_CONFIG_DEFAULTS } from '../../../src/config/systemConfig.defaults';

describe('utils', () => {
  describe('isValidEmail', () => {
    it('valid email', () => {
      expect(isValidEmail('test@example.com')).toBe(true);
    });

    it('invalid email', () => {
      expect(isValidEmail('bad-email')).toBe(false);
    });
  });

  describe('isValidPhoneNumber', () => {
    it('valid phone', () => {
      expect(isValidPhoneNumber('+14155552671')).toBe(true);
    });

    it('invalid phone', () => {
      expect(isValidPhoneNumber('123')).toBe(false);
    });
  });

  describe('normalizePhoneNumber', () => {
    it('normalizes a valid phone number to E.164', () => {
      expect(normalizePhoneNumber('+1 415 555 2671')).toBe('+14155552671');
    });

    it('returns null for an invalid phone number', () => {
      expect(normalizePhoneNumber('123')).toBeNull();
    });
  });

  describe('computeSessionTimes', () => {
    const now = new Date('2024-01-01T00:00:00Z');

    it('returns valid dates', () => {
      const { expiresAt, idleExpiresAt } = computeSessionTimes(
        { absoluteTtl: '1d', idleTtl: '8h' },
        now,
      );

      expect(expiresAt.getTime()).toBeGreaterThan(now.getTime());
      expect(idleExpiresAt.getTime()).toBeGreaterThan(now.getTime());
    });

    it('derives each bound from its own duration', () => {
      const { expiresAt, idleExpiresAt } = computeSessionTimes(
        { absoluteTtl: '1d', idleTtl: '8h' },
        now,
      );

      expect(expiresAt.toISOString()).toBe('2024-01-02T00:00:00.000Z');
      expect(idleExpiresAt.toISOString()).toBe('2024-01-01T08:00:00.000Z');
    });

    // The bug this replaced: both bounds came from equal hardcoded constants, so the
    // idle bound could never fire before absolute expiry.
    it('keeps the idle bound strictly inside the absolute bound on the shipped defaults', () => {
      const { expiresAt, idleExpiresAt } = computeSessionTimes(
        {
          absoluteTtl: SYSTEM_CONFIG_DEFAULTS.refresh_token_ttl ?? '1d',
          idleTtl: SYSTEM_CONFIG_DEFAULTS.session_idle_ttl!,
        },
        now,
      );

      expect(idleExpiresAt.getTime()).toBeLessThan(expiresAt.getTime());
    });

    it('rejects a malformed duration rather than silently defaulting', () => {
      expect(() => computeSessionTimes({ absoluteTtl: '1d', idleTtl: 'eight hours' }, now)).toThrow(
        /Invalid duration/,
      );
    });
  });

  describe('computeRotatedSessionTimes', () => {
    const chainStartedAt = new Date('2024-01-01T00:00:00Z');

    it('measures the absolute bound from the start of the chain, not from the refresh', () => {
      const now = new Date('2024-01-01T20:00:00Z');
      const { expiresAt } = computeRotatedSessionTimes(
        { absoluteTtl: '1d', idleTtl: '8h' },
        chainStartedAt,
        now,
      );

      expect(expiresAt.toISOString()).toBe('2024-01-02T00:00:00.000Z');
    });

    it('slides the idle bound from the refresh', () => {
      const now = new Date('2024-01-01T10:00:00Z');
      const { idleExpiresAt } = computeRotatedSessionTimes(
        { absoluteTtl: '1d', idleTtl: '8h' },
        chainStartedAt,
        now,
      );

      expect(idleExpiresAt.toISOString()).toBe('2024-01-01T18:00:00.000Z');
    });

    it('never lets the idle bound reach past the absolute one', () => {
      const now = new Date('2024-01-01T20:00:00Z');
      const { expiresAt, idleExpiresAt } = computeRotatedSessionTimes(
        { absoluteTtl: '1d', idleTtl: '8h' },
        chainStartedAt,
        now,
      );

      expect(idleExpiresAt.getTime()).toBe(expiresAt.getTime());
    });

    it('stays capped however often the chain is refreshed', () => {
      let now = chainStartedAt;
      let expiresAt = new Date(0);

      for (let i = 0; i < 100; i += 1) {
        now = new Date(now.getTime() + 15 * 60 * 1000);
        ({ expiresAt } = computeRotatedSessionTimes(
          { absoluteTtl: '1d', idleTtl: '8h' },
          chainStartedAt,
          now,
        ));
      }

      expect(expiresAt.toISOString()).toBe('2024-01-02T00:00:00.000Z');
    });
  });

  describe('parseDurationToSeconds', () => {
    it('parses seconds', () => {
      expect(parseDurationToSeconds('10s')).toBe(10);
    });

    it('parses minutes', () => {
      expect(parseDurationToSeconds('5m')).toBe(300);
    });

    it('parses hours', () => {
      expect(parseDurationToSeconds('1h')).toBe(3600);
    });

    it('parses days', () => {
      expect(parseDurationToSeconds('1d')).toBe(86400);
    });

    it('parses weeks', () => {
      expect(parseDurationToSeconds('1w')).toBe(604800);
    });

    it('throws on invalid input', () => {
      expect(() => parseDurationToSeconds('bad')).toThrow();
    });

    it('throws on empty', () => {
      expect(() => parseDurationToSeconds('')).toThrow();
    });
  });

  describe('hashSha256', () => {
    it('produces deterministic hash', () => {
      const hash1 = hashSha256('test');
      const hash2 = hashSha256('test');

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });
  });

  describe('hashDeviceFingerprint', () => {
    it('hashes both values', () => {
      const result = hashDeviceFingerprint('127.0.0.1', 'agent');

      expect(result.ip_hash).toBeDefined();
      expect(result.user_agent_hash).toBeDefined();
    });

    it('handles missing values', () => {
      const result = hashDeviceFingerprint();

      expect(result.ip_hash).toBeNull();
      expect(result.user_agent_hash).toBeNull();
    });
  });
});
