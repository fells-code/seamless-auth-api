import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { importPKCS8, importSPKI, jwtVerify, SignJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/utils/secretsStore.js', () => ({
  getSecret: vi.fn(),
}));

/**
 * The dev key store against a real directory: what survives on disk is what the next
 * container sees, so these exercise files rather than a mocked fs.
 */
let keyDir: string;

async function loadStore() {
  vi.resetModules();
  vi.stubEnv('NODE_ENV', 'development');
  vi.stubEnv('SEAMLESS_DEV_KEYS_DIR', keyDir);
  return import('../../../src/utils/signingKeyStore.js');
}

function rfc7638Thumbprint(publicKeyPem: string) {
  const { e, n } = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
  return crypto
    .createHash('sha256')
    .update(`{"e":"${e}","kty":"RSA","n":"${n}"}`)
    .digest('base64url');
}

beforeEach(() => {
  keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seamless-dev-keys-'));
});

afterEach(() => {
  fs.rmSync(keyDir, { recursive: true, force: true });
});

describe('dev signing key', () => {
  it('defaults to ./keys/dev and honours SEAMLESS_DEV_KEYS_DIR', async () => {
    vi.resetModules();
    vi.stubEnv('SEAMLESS_DEV_KEYS_DIR', '');
    const store = await import('../../../src/utils/signingKeyStore.js');
    expect(store.getDevKeyDir()).toBe(path.resolve('./keys/dev'));

    vi.stubEnv('SEAMLESS_DEV_KEYS_DIR', keyDir);
    expect(store.getDevKeyDir()).toBe(path.resolve(keyDir));
  });

  it('creates the key pair eagerly in the configured directory', async () => {
    const store = await loadStore();

    expect(store.getDevSigningKey()).toBeNull();

    const key = store.initDevSigningKey();

    expect(key).not.toBeNull();
    expect(fs.readFileSync(path.join(keyDir, 'private.pem'), 'utf8')).toBe(key!.privateKeyPem);
    expect(fs.existsSync(path.join(keyDir, 'public.pem'))).toBe(true);
    expect(store.getDevSigningKey()?.kid).toBe(key!.kid);
  });

  it('does nothing in production', async () => {
    vi.resetModules();
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('SEAMLESS_DEV_KEYS_DIR', keyDir);
    const store = await import('../../../src/utils/signingKeyStore.js');

    expect(store.initDevSigningKey()).toBeNull();
    expect(fs.readdirSync(keyDir)).toEqual([]);
  });

  it('keeps an existing key across restarts', async () => {
    const first = (await loadStore()).initDevSigningKey();
    const second = (await loadStore()).initDevSigningKey();

    expect(second!.kid).toBe(first!.kid);
    expect(second!.privateKeyPem).toBe(first!.privateKeyPem);
  });

  it('derives the kid from the RFC 7638 thumbprint of the public key', async () => {
    const key = (await loadStore()).initDevSigningKey()!;

    expect(key.kid).toMatch(/^dev-[A-Za-z0-9_-]{16}$/);
    expect(key.kid).toBe(`dev-${rfc7638Thumbprint(key.publicKeyPem).slice(0, 16)}`);
  });

  it('gives a regenerated key a new kid', async () => {
    const first = (await loadStore()).initDevSigningKey()!;

    fs.rmSync(path.join(keyDir, 'private.pem'));
    fs.rmSync(path.join(keyDir, 'public.pem'));

    const second = (await loadStore()).initDevSigningKey()!;

    expect(second.kid).not.toBe(first.kid);
    expect(second.kid).not.toBe('dev-main');
  });

  it('derives the public key when only private.pem survived', async () => {
    const original = (await loadStore()).initDevSigningKey()!;
    fs.rmSync(path.join(keyDir, 'public.pem'));

    const store = await loadStore();
    const key = store.getDevSigningKey();

    expect(key?.kid).toBe(original.kid);
    expect(key?.publicKeyPem).toBe(original.publicKeyPem);
    expect(await store.getPublicKeyByKid(original.kid)).toBe(original.publicKeyPem);
  });

  it('signs with the derived kid and verifies a token by it', async () => {
    const store = await loadStore();
    store.initDevSigningKey();

    const { kid, privateKeyPem } = await store.getSigningKey();
    const token = await new SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'RS256', kid })
      .sign(await importPKCS8(privateKeyPem, 'RS256'));

    const { payload } = await jwtVerify(token, async (header) =>
      importSPKI((await store.getPublicKeyByKid(header.kid!))!, 'RS256'),
    );
    expect(payload.sub).toBe('user-1');
    expect(await store.getPublicKeyByKid('dev-main')).toBeNull();
  });
});
