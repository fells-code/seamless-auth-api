import { vi, describe, expect, it } from 'vitest';

vi.unmock('../../../src/utils/utils');

import {
  isValidEmail,
  isValidPhoneNumber,
  computeSessionTimes,
  normalizePhoneNumber,
  parseDurationToSeconds,
  hashSha256,
  hashDeviceFingerprint,
} from '../../../src/utils/utils';

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
    it('returns valid dates', () => {
      const now = new Date('2024-01-01T00:00:00Z');
      const { expiresAt, idleExpiresAt } = computeSessionTimes(now);

      expect(expiresAt.getTime()).toBeGreaterThan(now.getTime());
      expect(idleExpiresAt.getTime()).toBeGreaterThan(now.getTime());
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
