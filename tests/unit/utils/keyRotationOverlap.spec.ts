import { generateKeyPairSync } from 'crypto';
import { importPKCS8, importSPKI, jwtVerify, SignJWT } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/utils/secretsStore.js', () => ({
  getSecret: vi.fn(),
}));

/**
 * The rotation contract, exercised end to end with real keys rather than asserted
 * about.
 *
 * A rotation is an overlap: the incoming key is published alongside the outgoing one,
 * the active kid flips, and the outgoing key stays published until every token it
 * signed has expired. Nothing here writes keys. The server reads the document, and
 * whatever manages the secrets owns it (seamless-iac ADR 0011).
 *
 * The property that makes it work is that verification resolves a key by the `kid` in
 * the token's own header, so a token outlives the key's time as the signer.
 */
function keypair() {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

const outgoing = keypair();
const incoming = keypair();

const publicKeysDocument = JSON.stringify({
  keys: [
    { kid: 'key_a', pem: outgoing.publicKey, createdAt: '2026-01-01T00:00:00.000Z' },
    { kid: 'key_b', pem: incoming.publicKey, createdAt: '2026-06-01T00:00:00.000Z' },
  ],
});

/** Serves the secrets the way the deployment does, by name rather than call order. */
function serveSecrets(activeKid: string) {
  return async (name: string) => {
    if (name === 'SEAMLESS_JWKS_ACTIVE_KID') return activeKid;
    if (name === 'SEAMLESS_JWKS_PUBLIC_KEYS') return publicKeysDocument;
    if (name === 'SEAMLESS_JWKS_KEY_key_a_PRIVATE') return outgoing.privateKey;
    if (name === 'SEAMLESS_JWKS_KEY_key_b_PRIVATE') return incoming.privateKey;
    throw new Error(`Secret "${name}" is not defined.`);
  };
}

async function loadStore(activeKid: string) {
  vi.resetModules();
  vi.stubEnv('NODE_ENV', 'production');

  const { getSecret } = await import('../../../src/utils/secretsStore.js');
  (getSecret as ReturnType<typeof vi.fn>).mockImplementation(serveSecrets(activeKid));

  return import('../../../src/utils/signingKeyStore.js');
}

async function signWith(privateKeyPem: string, kid: string) {
  return new SignJWT({ sub: 'user-1' })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(await importPKCS8(privateKeyPem, 'RS256'));
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe('signing key rotation overlap', () => {
  it('signs with the active key and no other', async () => {
    const before = await loadStore('key_a');
    expect((await before.getSigningKey()).kid).toBe('key_a');

    const after = await loadStore('key_b');
    expect((await after.getSigningKey()).kid).toBe('key_b');
  });

  it('keeps resolving the outgoing key after the active kid has moved on', async () => {
    const store = await loadStore('key_b');

    expect(await store.getPublicKeyByKid('key_a')).toBe(outgoing.publicKey);
    expect(await store.getPublicKeyByKid('key_b')).toBe(incoming.publicKey);
  });

  /**
   * The acceptance criterion of #175: a token issued before a rotation stays valid for
   * its lifetime. Signed with the outgoing key, then verified against the key the
   * store hands back once the incoming key has taken over signing.
   */
  it('verifies a token signed before the rotation', async () => {
    const beforeRotation = await loadStore('key_a');
    const { kid, privateKeyPem } = await beforeRotation.getSigningKey();
    const token = await signWith(privateKeyPem, kid);

    const afterRotation = await loadStore('key_b');
    expect((await afterRotation.getSigningKey()).kid).toBe('key_b');

    const pem = await afterRotation.getPublicKeyByKid(kid);
    const { payload } = await jwtVerify(token, await importSPKI(pem!, 'RS256'));

    expect(payload.sub).toBe('user-1');
  });

  /**
   * Step three of the procedure. Once the retired key leaves the document the tokens
   * it signed stop verifying, which is why the docs tie that step to refresh_token_ttl
   * rather than to the rotation.
   */
  it('stops resolving a retired key once it leaves the document', async () => {
    vi.resetModules();
    vi.stubEnv('NODE_ENV', 'production');

    const { getSecret } = await import('../../../src/utils/secretsStore.js');
    (getSecret as ReturnType<typeof vi.fn>).mockImplementation(async (name: string) => {
      if (name === 'SEAMLESS_JWKS_ACTIVE_KID') return 'key_b';
      if (name === 'SEAMLESS_JWKS_PUBLIC_KEYS') {
        return JSON.stringify({
          keys: [{ kid: 'key_b', pem: incoming.publicKey, createdAt: '2026-06-01T00:00:00.000Z' }],
        });
      }
      throw new Error(`Secret "${name}" is not defined.`);
    });

    const store = await import('../../../src/utils/signingKeyStore.js');

    expect(await store.getPublicKeyByKid('key_a')).toBeNull();
    expect(await store.getPublicKeyByKid('key_b')).toBe(incoming.publicKey);
  });

  /**
   * The split that made this reachable: validateEnvs.sh required the unprefixed name
   * while verification read the prefixed one, so a deployment following the documented
   * contract booted and then failed every verification. Both names are now the same one.
   */
  it('reads the public keys document under the documented name', async () => {
    const store = await loadStore('key_b');
    const { getSecret } = await import('../../../src/utils/secretsStore.js');

    await store.getPublicKeyByKid('key_b');

    expect(getSecret).toHaveBeenCalledWith('SEAMLESS_JWKS_PUBLIC_KEYS');
  });
});
