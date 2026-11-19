import { describe, expect, it } from 'vitest';

import { classifyRefreshRefusal } from '../../../src/lib/refreshRefusal.js';
import {
  openReplayToken,
  refreshReplayWindowMs,
  sealReplayToken,
} from '../../../src/lib/refreshReplayToken.js';

const binding = {
  predecessorToken: 'predecessor-refresh-token',
  predecessorId: 'session-1',
  successorId: 'session-2',
};

describe('refreshReplayWindowMs', () => {
  it('defaults to five seconds', () => {
    expect(refreshReplayWindowMs({})).toBe(5_000);
    expect(refreshReplayWindowMs({ REFRESH_REPLAY_WINDOW_SECONDS: ' ' })).toBe(5_000);
  });

  it('reads the configured window and caps it at a minute', () => {
    expect(refreshReplayWindowMs({ REFRESH_REPLAY_WINDOW_SECONDS: '12' })).toBe(12_000);
    expect(refreshReplayWindowMs({ REFRESH_REPLAY_WINDOW_SECONDS: '3600' })).toBe(60_000);
  });

  it('is disabled by zero, a negative value or nonsense', () => {
    expect(refreshReplayWindowMs({ REFRESH_REPLAY_WINDOW_SECONDS: '0' })).toBe(0);
    expect(refreshReplayWindowMs({ REFRESH_REPLAY_WINDOW_SECONDS: '-3' })).toBe(0);
    expect(refreshReplayWindowMs({ REFRESH_REPLAY_WINDOW_SECONDS: 'soon' })).toBe(0);
  });
});

describe('sealReplayToken', () => {
  it('opens to the successor token for the holder of the predecessor token', () => {
    const sealed = sealReplayToken(binding, 'successor-refresh-token');

    expect(sealed).not.toContain('successor-refresh-token');
    expect(openReplayToken(binding, sealed)).toBe('successor-refresh-token');
  });

  it('does not open without the predecessor token', () => {
    const sealed = sealReplayToken(binding, 'successor-refresh-token');

    expect(openReplayToken({ ...binding, predecessorToken: 'guess' }, sealed)).toBeNull();
  });

  it('does not open when moved to another session pair', () => {
    const sealed = sealReplayToken(binding, 'successor-refresh-token');

    expect(openReplayToken({ ...binding, successorId: 'session-3' }, sealed)).toBeNull();
    expect(openReplayToken({ ...binding, predecessorId: 'session-0' }, sealed)).toBeNull();
  });

  it('refuses a tampered, truncated or unknown format', () => {
    const sealed = sealReplayToken(binding, 'successor-refresh-token');
    const [format, iv, ciphertext, tag] = sealed.split('.');

    expect(openReplayToken(binding, [format, iv, ciphertext, tag.slice(0, 8)].join('.'))).toBe(
      null,
    );
    expect(openReplayToken(binding, ['v2', iv, ciphertext, tag].join('.'))).toBeNull();
    expect(openReplayToken(binding, `${format}.${iv}`)).toBeNull();
  });
});

describe('classifyRefreshRefusal', () => {
  const now = new Date('2026-01-01T12:00:00Z');
  const past = new Date('2026-01-01T11:00:00Z');
  const future = new Date('2026-01-01T13:00:00Z');

  it('names why a session cannot be refreshed', () => {
    expect(
      classifyRefreshRefusal({ revokedAt: past, expiresAt: future, idleExpiresAt: future }, now),
    ).toBe('revoked');
    expect(
      classifyRefreshRefusal({ revokedAt: null, expiresAt: past, idleExpiresAt: past }, now),
    ).toBe('absolute_lifetime_reached');
    expect(
      classifyRefreshRefusal({ revokedAt: null, expiresAt: future, idleExpiresAt: past }, now),
    ).toBe('idle_timeout');
  });

  it('says nothing about a live session', () => {
    expect(
      classifyRefreshRefusal({ revokedAt: null, expiresAt: future, idleExpiresAt: future }, now),
    ).toBeNull();
  });
});
