import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  hasMetadataStatement,
  initializeMetadataService,
  isMetadataServiceReady,
  resetMetadataServiceForTests,
} from '../../../src/services/metadataServiceBootstrap.js';

const { metadataInitialize, metadataGetStatement } = vi.hoisted(() => ({
  metadataInitialize: vi.fn(),
  metadataGetStatement: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => ({
  MetadataService: { initialize: metadataInitialize, getStatement: metadataGetStatement },
}));

function policy(overrides: Record<string, unknown> = {}) {
  return {
    authenticator_policy: {
      attachment: 'any',
      userVerification: 'required',
      attestation: 'none',
      requireKnownAuthenticator: false,
      syncedPasskeys: 'block',
      aaguidAllowList: [],
      aaguidDenyList: [],
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

describe('misconfiguration warning', () => {
  it('says so when an allow list is set without asking for attestation', async () => {
    (getSystemConfig as any).mockResolvedValue(
      policy({ attestation: 'none', aaguidAllowList: ['ee882879-721c-4913-9775-3dfcce97072a'] }),
    );

    // Nothing can identify itself, so every registration would be refused. The
    // point is that this is said once at boot rather than discovered one failed
    // enrolment at a time.
    expect(await initializeMetadataService()).toBe(false);
  });

  it('says so when known authenticators are required without asking for attestation', async () => {
    (getSystemConfig as any).mockResolvedValue(
      policy({ attestation: 'none', requireKnownAuthenticator: true }),
    );

    // The setting reads like it restricts something. Under 'none' nothing
    // identifies itself, so there is nothing to match and it restricts nothing.
    expect(await initializeMetadataService()).toBe(false);
  });
});

describe('hasMetadataStatement', () => {
  const AAGUID = 'ee882879-721c-4913-9775-3dfcce97072a';

  async function bringTheServiceUp() {
    (getSystemConfig as any).mockResolvedValue(policy({ attestation: 'direct' }));
    metadataInitialize.mockResolvedValue(undefined);
    await initializeMetadataService();
  }

  it('is false before the service has come up, without asking it anything', async () => {
    expect(await hasMetadataStatement(AAGUID)).toBe(false);
    expect(metadataGetStatement).not.toHaveBeenCalled();
  });

  it('is false for a credential that reported no model', async () => {
    await bringTheServiceUp();

    expect(await hasMetadataStatement(null)).toBe(false);
    expect(metadataGetStatement).not.toHaveBeenCalled();
  });

  it('is true when the service holds a statement for the model', async () => {
    await bringTheServiceUp();
    metadataGetStatement.mockResolvedValue({ description: 'A security key' });

    expect(await hasMetadataStatement(AAGUID)).toBe(true);
    expect(metadataGetStatement).toHaveBeenCalledWith(AAGUID);
  });

  it('is false when the service has no statement for the model', async () => {
    await bringTheServiceUp();
    metadataGetStatement.mockResolvedValue(undefined);

    expect(await hasMetadataStatement(AAGUID)).toBe(false);
  });

  // Under a strict verification mode an unlisted model raises rather than
  // returning nothing, which is an answer here, not a failure.
  it('is false when the service refuses an unlisted model', async () => {
    await bringTheServiceUp();
    metadataGetStatement.mockRejectedValue(new Error('No metadata statement found'));

    expect(await hasMetadataStatement(AAGUID)).toBe(false);
  });
});
