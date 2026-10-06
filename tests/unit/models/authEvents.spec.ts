import { readFileSync } from 'fs';
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

// A column the chain does not hash can be edited without the integrity check noticing.
describe('AuthEvent audit chain coverage', () => {
  const NOT_HASHED = new Set(['updated_at', 'prev_hash', 'hash']);

  it('hashes every column the model defines', () => {
    const sequelize = new Sequelize({ dialect: 'sqlite', storage: ':memory:', logging: false });
    initializeAuthEventModel(sequelize);

    const migration = readFileSync(
      new URL('../../../src/migrations/20261008130000-protect-auth-events.cjs', import.meta.url),
      'utf8',
    );
    const payload = migration.slice(
      migration.indexOf('jsonb_build_array('),
      migration.indexOf(')::text'),
    );

    const columns = Object.values(AuthEvent.getAttributes()).map(
      (attribute) => attribute.field ?? '',
    );
    const unhashed = columns.filter(
      (column) => !NOT_HASHED.has(column) && !payload.includes(`e.${column}`),
    );

    expect(unhashed).toEqual([]);
  });
});
