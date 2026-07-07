import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { getSecret } from '../../../src/utils/secretsStore.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { __resetJwksCache } from '../../../src/controllers/jwks.js';

vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs');

  return {
    ...actual,
    readFileSync: vi.fn(),
  };
});

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('jose', () => ({
  importSPKI: vi.fn(),
  exportJWK: vi.fn(),
}));

vi.mock('../../../src/utils/secretsStore.js', () => ({
  getSecret: vi.fn(),
}));

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  __resetJwksCache();
  (getSystemConfig as any).mockResolvedValue({
    default_roles: ['user'],
  });
});

afterAll(() => {
  vi.unstubAllEnvs();
});

describe('JWKS - Production Mode', () => {
  it('returns jwks from secrets', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    const { importSPKI, exportJWK } = await import('jose');

    (getSecret as any).mockResolvedValue(
      JSON.stringify({
        keys: [
          {
            pem: 'fake-pem',
            kid: 'key-1',
          },
        ],
      }),
    );

    (importSPKI as any).mockResolvedValue('key');
    (exportJWK as any).mockResolvedValue({
      kty: 'RSA',
      n: 'abc',
      e: 'AQAB',
    });

    const res = await request(app).get('/.well-known/jwks.json');

    expect(res.status).toBe(200);
    expect(res.body.keys[0].kid).toBe('key-1');

    expect(getSecret).toHaveBeenCalledWith('JWKS_PUBLIC_KEYS');
    expect(res.headers['cache-control']).toContain('max-age=300');
  });
});

describe('JWKS - Error Handling', () => {
  it('returns 500 when secrets fail', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    (getSecret as any).mockRejectedValue(new Error('boom'));

    const res = await request(app).get('/.well-known/jwks.json');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'JWKS unavailable' });
  });
});

describe('JWKS - Caching', () => {
  it('uses cached jwks on second call', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    const { importSPKI, exportJWK } = await import('jose');

    (getSecret as any).mockResolvedValue(
      JSON.stringify({
        keys: [{ pem: 'fake-pem', kid: 'cached-key' }],
      }),
    );

    (importSPKI as any).mockResolvedValue('key');
    (exportJWK as any).mockResolvedValue({
      kty: 'RSA',
    });

    await request(app).get('/.well-known/jwks.json');
    await request(app).get('/.well-known/jwks.json');

    expect(getSecret).toHaveBeenCalledTimes(1);
  });
});
