import { describe, expect, it } from 'vitest';

import type { SystemConfig } from '../../../src/schemas/systemConfig.schema.js';
import { createPatchSystemConfigSchema } from '../../../src/schemas/systemConfig.patch.schema.js';

const existing = {
  available_roles: ['user', 'admin'],
  default_roles: ['user'],
} as unknown as SystemConfig;

describe('createPatchSystemConfigSchema', () => {
  it('accepts a patch that keeps default roles available', () => {
    const schema = createPatchSystemConfigSchema(existing);

    const parsed = schema.safeParse({ available_roles: ['user', 'admin', 'auditor'] });

    expect(parsed.success).toBe(true);
  });

  it('rejects removing an available role that is currently a default', () => {
    const schema = createPatchSystemConfigSchema(existing);

    const parsed = schema.safeParse({ available_roles: ['admin'] });

    expect(parsed.success).toBe(false);
    expect(
      parsed.success === false &&
        parsed.error.issues.some(
          (i) => i.message === 'Cannot remove roles currently set as default',
        ),
    ).toBe(true);
  });

  it('rejects a default role that is not part of available roles', () => {
    const schema = createPatchSystemConfigSchema(existing);

    const parsed = schema.safeParse({ default_roles: ['superuser'] });

    expect(parsed.success).toBe(false);
    expect(
      parsed.success === false &&
        parsed.error.issues.some(
          (i) => i.message === 'All default roles must exist in available_roles',
        ),
    ).toBe(true);
  });
});
