import { describe, expect, it } from 'vitest';

import { passkeyDeviceBinding } from '../../../src/lib/passkeyAssurance.js';

describe('passkeyDeviceBinding', () => {
  it('awards hardware assurance only to an attested device-bound registration', () => {
    expect(
      passkeyDeviceBinding(
        { deviceType: 'singleDevice', attestationVerified: true },
        'singleDevice',
      ),
    ).toEqual({ deviceBound: true });
    expect(
      passkeyDeviceBinding(
        { deviceType: 'singleDevice', attestationVerified: null },
        'singleDevice',
      ),
    ).toEqual({ deviceBound: false });
    expect(
      passkeyDeviceBinding({ deviceType: 'multiDevice', attestationVerified: true }, 'multiDevice'),
    ).toEqual({ deviceBound: false });
  });

  it('refuses a flag that differs from registration in either direction', () => {
    expect(
      passkeyDeviceBinding(
        { deviceType: 'multiDevice', attestationVerified: true },
        'singleDevice',
      ),
    ).toBeNull();
    expect(
      passkeyDeviceBinding(
        { deviceType: 'singleDevice', attestationVerified: true },
        'multiDevice',
      ),
    ).toBeNull();
  });

  it('gives a credential registered before the device type was stored no hardware assurance', () => {
    expect(
      passkeyDeviceBinding({ deviceType: null, attestationVerified: null }, 'singleDevice'),
    ).toEqual({ deviceBound: false });
  });
});
