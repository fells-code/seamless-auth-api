import { describe, expect, it } from 'vitest';

import { CredentialResponseSchema } from '../../../src/schemas/credential.responses.js';
import { serializeCredential } from '../../../src/services/apiResponseSerializers.js';

describe('CredentialResponseSchema', () => {
  it('accepts a serialized cross-device passkey end to end', () => {
    const serialized = serializeCredential({
      id: 'credential-hybrid',
      userId: 'user-1',
      publicKey: 'public-key',
      counter: 0,
      transports: ['hybrid'],
      deviceType: 'multiDevice',
      backedUp: true,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
    });

    const parsed = CredentialResponseSchema.safeParse(serialized);

    // The serializer used to drop `hybrid`, and the schema used to reject it, so a
    // cross-device passkey reported an empty transport list to every client.
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.transports).toEqual(['hybrid']);
  });

  it('carries the authenticator model through to the response', () => {
    const serialized = serializeCredential({
      id: 'credential-1',
      counter: 0,
      backedUp: false,
      aaguid: 'ee882879-721c-4913-9775-3dfcce97072a',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
    });

    const parsed = CredentialResponseSchema.safeParse(serialized);

    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.aaguid).toBe('ee882879-721c-4913-9775-3dfcce97072a');
  });

  it('reports a credential registered before the model was recorded as unknown', () => {
    const serialized = serializeCredential({
      id: 'credential-1',
      counter: 0,
      backedUp: false,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
    });

    const parsed = CredentialResponseSchema.safeParse(serialized);

    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.aaguid).toBeUndefined();
  });

  it('still rejects a transport that is not in the WebAuthn set', () => {
    const parsed = CredentialResponseSchema.safeParse({
      id: 'credential-1',
      userId: 'user-1',
      publicKey: 'public-key',
      counter: 0,
      transports: ['bogus'],
      backedUp: false,
      backedup: false,
      createdAt: '2026-01-01T00:00:00.000Z',
    });

    expect(parsed.success).toBe(false);
  });
});
