import { Sequelize } from 'sequelize';
import { beforeAll, describe, expect, it, vi } from 'vitest';

vi.unmock('../../../src/models/authEvents.js');

import initializeAuthEventModel, { AuthEvent } from '../../../src/models/authEvents.js';

describe('AuthEvent metadata redaction hooks', () => {
  beforeAll(() => {
    const sequelize = new Sequelize({ dialect: 'sqlite', storage: ':memory:', logging: false });
    initializeAuthEventModel(sequelize);
  });

  it('redacts sensitive metadata before validation', async () => {
    const event = AuthEvent.build({
      type: 'login',
      metadata: { email: 'user@example.com', provider: 'google' },
    });

    await AuthEvent.runHooks('beforeValidate', event, {});

    expect(event.metadata).toEqual({ email: '[REDACTED]', provider: 'google' });
  });

  it('redacts sensitive metadata for every event in a bulk create', async () => {
    const first = AuthEvent.build({ type: 'login', metadata: { token: 'secret' } });
    const second = AuthEvent.build({ type: 'logout', metadata: { phone: '+15555550123' } });

    await AuthEvent.runHooks('beforeBulkCreate', [first, second], {});

    expect(first.metadata).toEqual({ token: '[REDACTED]' });
    expect(second.metadata).toEqual({ phone: '[REDACTED]' });
  });
});
