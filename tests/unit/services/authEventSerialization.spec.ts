import { describe, expect, it } from 'vitest';

import {
  serializeAuthEvent,
  serializeAuthEvents,
} from '../../../src/services/authEventSerialization.js';

describe('auth event serialization', () => {
  it('redacts legacy sensitive metadata when returning auth events', () => {
    const event = {
      toJSON: () => ({
        id: 'event-1',
        type: 'system_config_updated',
        metadata: {
          before: {
            email: 'user@example.com',
            phoneVerificationToken: '123456',
          },
          after: {
            roles: ['admin'],
            prfSalt: 'salt-value',
          },
        },
      }),
    };

    expect(serializeAuthEvent(event)).toEqual({
      id: 'event-1',
      type: 'system_config_updated',
      metadata: {
        before: {
          email: '[REDACTED]',
          phoneVerificationToken: '[REDACTED]',
        },
        after: {
          roles: ['admin'],
          prfSalt: '[REDACTED]',
        },
      },
    });
  });

  it('returns non-object inputs unchanged', () => {
    expect(serializeAuthEvent(null)).toBeNull();
    expect(serializeAuthEvent('not-an-event')).toBe('not-an-event');
  });

  it('redacts plain event objects that do not expose toJSON', () => {
    expect(
      serializeAuthEvent({
        id: 'event-2',
        metadata: { email: 'user@example.com' },
      }),
    ).toEqual({
      id: 'event-2',
      metadata: { email: '[REDACTED]' },
    });
  });

  it('serializes a list of auth events', () => {
    expect(serializeAuthEvents([{ id: 'event-3', metadata: null }, null])).toEqual([
      { id: 'event-3', metadata: null },
      null,
    ]);
  });
});
