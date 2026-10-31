import request from 'supertest';
import { Application } from 'express';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Session } from '../../../src/models/sessions.js';
import { SystemConfig } from '../../../src/models/systemConfig.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

// Production fetches go through the guarded node:https path, which a fetch stub cannot
// answer, so discovery itself is replaced to reach the policy check behind it.
vi.mock('../../../src/services/oauthDiscovery.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/services/oauthDiscovery.js')>()),
  discoverOAuthEndpoints: vi.fn(async () => ({
    issuer: 'https://idp.example.com',
    authorizationUrl: 'https://idp.example.com/authorize',
    tokenUrl: 'http://idp.example.com/token',
    userInfoUrl: 'https://idp.example.com/userinfo',
    jwksUri: 'https://idp.example.com/jwks',
  })),
}));

let app: Application;

const provider = {
  id: 'acme',
  name: 'Acme',
  enabled: true,
  clientId: 'acme-client',
  clientSecretEnv: 'ACME_CLIENT_SECRET',
  issuer: 'https://idp.example.com',
  scopes: ['openid'],
};

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());
  (getSystemConfig as any).mockResolvedValue(buildSystemConfig({ oauth_providers: [provider] }));
  (SystemConfig.findByPk as any).mockResolvedValue({ key: 'oauth_providers', value: [provider] });
});

describe('POST /system-config/oauth-providers/:id/discovery in production', () => {
  it('refuses discovered endpoints the provider policy does not allow', async () => {
    vi.stubEnv('NODE_ENV', 'production');

    const res = await request(app).post('/system-config/oauth-providers/acme/discovery');

    vi.unstubAllEnvs();
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid OAuth provider');
  });
});
