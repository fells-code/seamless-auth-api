import { AuthenticatorPolicySchema } from '@seamless-auth/types';
import { describe, expect, it } from 'vitest';

import { SYSTEM_CONFIG_DEFAULTS } from '../../../src/config/systemConfig.defaults';

describe('SYSTEM_CONFIG_DEFAULTS', () => {
  // Guards drift this default has already suffered: the schema package gained fields
  // while a hand-written restatement here kept the old shape, so a freshly seeded
  // deployment disagreed with the generated contract until someone noticed.
  it('seeds exactly the authenticator policy the schema defines', () => {
    expect(SYSTEM_CONFIG_DEFAULTS.authenticator_policy).toEqual(
      AuthenticatorPolicySchema.parse({}),
    );
  });

  it('refuses synced passkeys unless a deployment opts in', () => {
    expect(SYSTEM_CONFIG_DEFAULTS.authenticator_policy?.syncedPasskeys).toBe('block');
  });
});
