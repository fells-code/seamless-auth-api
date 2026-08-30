import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  initializeMetadataService,
  isMetadataServiceReady,
  resetMetadataServiceForTests,
} from '../../../src/services/metadataServiceBootstrap.js';

const { metadataInitialize } = vi.hoisted(() => ({ metadataInitialize: vi.fn() }));

vi.mock('@simplewebauthn/server', () => ({
  MetadataService: { initialize: metadataInitialize },
}));

function policy(overrides: Record<string, unknown> = {}) {
  return {
    authenticator_policy: {
      attachment: 'any',
      userVerification: 'required',
      attestation: 'none',
      requireKnownAuthenticator: false,
      ...overrides,
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  resetMetadataServiceForTests();
});

describe('initializeMetadataService', () => {
  it('does nothing when the deployment does not ask for attestation', async () => {
    (getSystemConfig as any).mockResolvedValue(policy({ attestation: 'none' }));

    expect(await initializeMetadataService()).toBe(false);
    // No blob download, so no network dependency at boot for deployments that
    // would never consult it.
    expect(metadataInitialize).not.toHaveBeenCalled();
    expect(isMetadataServiceReady()).toBe(false);
  });

  it('initializes permissively when unlisted authenticators are allowed', async () => {
    (getSystemConfig as any).mockResolvedValue(policy({ attestation: 'direct' }));
    metadataInitialize.mockResolvedValue(undefined);

    expect(await initializeMetadataService()).toBe(true);
    expect(metadataInitialize).toHaveBeenCalledWith({ verificationMode: 'permissive' });
    expect(isMetadataServiceReady()).toBe(true);
  });

  it('initializes strictly when only known authenticators are allowed', async () => {
    (getSystemConfig as any).mockResolvedValue(
      policy({ attestation: 'direct', requireKnownAuthenticator: true }),
    );
    metadataInitialize.mockResolvedValue(undefined);

    await initializeMetadataService();

    expect(metadataInitialize).toHaveBeenCalledWith({ verificationMode: 'strict' });
  });

  // An auth server that will not start because a metadata blob is unreachable is
  // worse than one that starts without metadata validation.
  it('survives a metadata blob that cannot be fetched', async () => {
    (getSystemConfig as any).mockResolvedValue(policy({ attestation: 'direct' }));
    metadataInitialize.mockRejectedValue(new Error('network down'));

    expect(await initializeMetadataService()).toBe(false);
    expect(isMetadataServiceReady()).toBe(false);
  });

  it('survives config being unreadable', async () => {
    (getSystemConfig as any).mockRejectedValue(new Error('no database'));

    expect(await initializeMetadataService()).toBe(false);
    expect(metadataInitialize).not.toHaveBeenCalled();
  });
});
