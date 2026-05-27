import { describe, expect, it } from 'vitest';

import { serializeAuthEvent } from '../../../src/services/authEventSerialization.js';

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
});
