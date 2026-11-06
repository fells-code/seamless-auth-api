import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app';
import { SystemConfig } from '../../../src/models/systemConfig.js';
import { User } from '../../../src/models/users.js';
import {
  getSystemConfig,
  invalidateSystemConfigCache,
} from '../../../src/config/getSystemConfig.js';
import { OidcClient } from '../../../src/models/oidcClients.js';
import { Session } from '../../../src/models/sessions.js';
import { buildFreshStepUpSession } from '../../factories/sessionFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';

vi.mock('../../../src/models/oidcClients.js', () => ({
  OidcClient: { findByPk: vi.fn() },
}));

const CLI_CLIENT = {
  id: 'seamless-cli',
  firstParty: true,
  clientType: 'public',
  tokenEndpointAuthMethod: 'none',
  redirectUris: ['http://127.0.0.1/callback'],
  sessionExchangeEnabled: true,
  disabledAt: null,
};

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  (Session.findOne as any).mockResolvedValue(buildFreshStepUpSession());

  (getSystemConfig as any).mockResolvedValue({
    available_roles: ['user', 'admin'],
    default_roles: ['user'],
  });
});

describe('GET /system-config/roles', () => {
  it('returns available roles', async () => {
    const res = await request(app).get('/system-config/roles');

    expect(res.status).toBe(200);
    expect(res.body.roles).toEqual(['user', 'admin']);
  });
});

describe('GET /system-config/admin', () => {
  it('returns system config', async () => {
    const config = buildSystemConfig();

    (SystemConfig.findAll as any).mockResolvedValue(
      Object.entries(config).map(([key, value]) => ({
        key,
        value,
      })),
    );

    const res = await request(app).get('/system-config/admin');

    expect(res.status).toBe(200);
    expect(res.body.app_name).toBe('SeamlessAuth');
    expect(res.body.available_roles).toEqual(['user', 'admin']);
  });

  it('returns 500 when schema invalid', async () => {
    (SystemConfig.findAll as any).mockResolvedValue([{ key: 'app_name', value: 'SeamlessAuth' }]);

    const res = await request(app).get('/system-config/admin');

    expect(res.status).toBe(500);
  });
});

describe('PATCH /system-config/admin', () => {
  it('updates system config', async () => {
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
    expect(SystemConfig.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ updatedBy: 'user-1' }),
      expect.anything(),
    );
  });

  it('refuses OAuth providers that fail the provider policy', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({
        oauth_providers: [
          {
            id: 'acme',
            name: 'Acme',
            enabled: true,
            clientId: 'client',
            clientSecretEnv: 'ACME_CLIENT_SECRET',
            authorizationUrl: 'https://idp.example.com/authorize',
            tokenUrl: 'http://idp.example.com/token',
            userInfoUrl: 'https://idp.example.com/userinfo',
            scopes: ['openid'],
          },
        ],
      });

    vi.unstubAllEnvs();
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid OAuth provider');
    expect(res.body.details).toEqual(['acme: tokenUrl must use https']);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('refuses OAuth providers in production while OAUTH_STATE_SECRET is unset', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('OAUTH_STATE_SECRET', '');
    (User.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({
        oauth_providers: [
          {
            id: 'acme',
            name: 'Acme',
            clientId: 'client',
            clientSecretEnv: 'ACME_CLIENT_SECRET',
            authorizationUrl: 'https://idp.example.com/authorize',
            tokenUrl: 'https://idp.example.com/token',
            userInfoUrl: 'https://idp.example.com/userinfo',
          },
        ],
      });

    vi.unstubAllEnvs();
    expect(res.status).toBe(409);
    expect(res.body).toEqual({ error: 'secret_required', variable: 'OAUTH_STATE_SECRET' });
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('accepts scoped role names', async () => {
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin:read', 'admin:write'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('refuses to enable the OpenID Provider without an issuer or keys', async () => {
    (User.findAll as any).mockResolvedValue([]);
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig({ oidc_issuer: null }));

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ oidc_provider_enabled: true });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid OpenID Provider config');
    expect(res.body.details).toContain('oidc_provider_enabled needs oidc_issuer');
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('accepts an issuer rpid covers while the provider stays off', async () => {
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig({ rpid: 'example.com' }));

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ oidc_issuer: 'https://login.example.com' });

    expect(res.status).toBe(200);
  });

  it('stores hosted page branding and refreshes the cached config', async () => {
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);
    const hosted_ui = {
      logoUrl: 'https://cdn.example.com/logo.svg',
      colors: { primary: '#1a73e8' },
    };

    const res = await request(app).patch('/system-config/admin').send({ hosted_ui });

    expect(res.status).toBe(200);
    expect(SystemConfig.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ key: 'hosted_ui', value: hosted_ui }),
      expect.anything(),
    );
    expect(invalidateSystemConfigCache).toHaveBeenCalled();
  });

  it.each([
    { colors: { primary: 'red;} body{display:none' } },
    { logoUrl: 'http://cdn.example.com/logo.svg' },
    { logoUrl: "https://cdn.example.com/logo.svg')" },
    { fontFamily: "'Inter" },
    { script: '<script>' },
  ])('refuses hosted page branding %j', async (hosted_ui) => {
    const res = await request(app).patch('/system-config/admin').send({ hosted_ui });

    expect(res.status).toBe(400);
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  it('rejects invalid payload', async () => {
    const res = await request(app).patch('/system-config/admin').send({ invalid: true });

    expect(res.status).toBe(400);
  });

  it('rejects removing role in use', async () => {
    (User.findAll as any).mockResolvedValue([{ roles: ['admin'] }]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Role removal blocked');
  });

  it('rejects empty update', async () => {
    const res = await request(app).patch('/system-config/admin').send({});

    expect(res.status).toBe(400);
  });

  it('handles a null user list when computing roles in use', async () => {
    (User.findAll as any).mockResolvedValue(null);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('returns 400 when the payload fails the dynamic (config-aware) schema', async () => {
    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['admin'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid system config payload');
  });

  it('allows keeping a role that is still available and in use', async () => {
    (User.findAll as any).mockResolvedValue([{ roles: ['user'] }]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('tolerates users without any roles when computing roles in use', async () => {
    (User.findAll as any).mockResolvedValue([{ roles: null }]);
    (SystemConfig.findAll as any).mockResolvedValue([]);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ available_roles: ['user', 'admin'] });

    expect(res.status).toBe(200);
  });
});

describe('GET /system-config/roles (additional branches)', () => {
  it('returns an empty roles list when none are configured', async () => {
    (getSystemConfig as any).mockResolvedValue({
      available_roles: undefined,
      default_roles: ['user'],
    });

    const res = await request(app).get('/system-config/roles');

    expect(res.status).toBe(200);
    expect(res.body.roles).toEqual([]);
  });
});

describe('GET /system-config/public', () => {
  it('returns the configured login methods', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey', 'phone_otp'],
      passkey_login_fallback_enabled: true,
    });

    const res = await request(app).get('/system-config/public');

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey', 'phone_otp']);
  });

  // A client with no methods has nothing to render, so a config that never had
  // login_methods written answers with the defaults rather than an empty list.
  it('falls back to the defaults when the stored config has no login methods', async () => {
    const res = await request(app).get('/system-config/public');

    expect(res.status).toBe(200);
    expect(res.body.loginMethods).toEqual(['passkey', 'magic_link']);
  });

  it('exposes only what the sign-in screens need', async () => {
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig());

    const res = await request(app).get('/system-config/public');

    expect(res.status).toBe(200);
    expect(Object.keys(res.body)).toEqual(['loginMethods', 'recoveryCodes', 'accountRecovery']);
  });

  it('says whether recovery codes can be used', async () => {
    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ recovery_codes: { enabled: false, requireAtEnrollment: false } }),
    );

    const res = await request(app).get('/system-config/public');

    expect(res.body.recoveryCodes).toBe(false);
  });

  it('says whether self-service account recovery is on, which it is not by default', async () => {
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig());
    expect((await request(app).get('/system-config/public')).body.accountRecovery).toBe(false);

    (getSystemConfig as any).mockResolvedValue(
      buildSystemConfig({ account_recovery: { enabled: true, delay: '24h' } }),
    );
    expect((await request(app).get('/system-config/public')).body.accountRecovery).toBe(true);
  });

  describe('oidcProvider', () => {
    const advertising = {
      oidc_provider_enabled: true,
      oidc_issuer: 'https://login.example.com',
      oidc_cli_client_id: CLI_CLIENT.id,
    };

    it('advertises the issuer and client when every condition holds', async () => {
      (getSystemConfig as any).mockResolvedValue(buildSystemConfig(advertising));
      (OidcClient.findByPk as any).mockResolvedValue(CLI_CLIENT);

      const res = await request(app).get('/system-config/public');

      expect(res.body.oidcProvider).toEqual({
        issuer: 'https://login.example.com',
        cliClientId: CLI_CLIENT.id,
      });
      expect(res.headers['cache-control']).toBe('no-store');
    });

    it.each([
      ['the provider is off', { oidc_provider_enabled: false }],
      ['there is no issuer', { oidc_issuer: null }],
      ['there is no client', { oidc_cli_client_id: null }],
    ])('is absent, and reads no application, when %s', async (_name, overrides) => {
      (getSystemConfig as any).mockResolvedValue(
        buildSystemConfig({ ...advertising, ...overrides }),
      );

      const res = await request(app).get('/system-config/public');

      expect(res.body).not.toHaveProperty('oidcProvider');
      expect(OidcClient.findByPk).not.toHaveBeenCalled();
    });

    it.each([
      ['does not exist', null],
      ['is disabled', { ...CLI_CLIENT, disabledAt: new Date() }],
      ['has exchange off', { ...CLI_CLIENT, sessionExchangeEnabled: false }],
    ])('is absent when the application %s', async (_name, client) => {
      (getSystemConfig as any).mockResolvedValue(buildSystemConfig(advertising));
      (OidcClient.findByPk as any).mockResolvedValue(client);

      const res = await request(app).get('/system-config/public');

      expect(res.body).not.toHaveProperty('oidcProvider');
    });
  });
});

describe('PATCH /system-config/admin oidc_cli_client_id', () => {
  beforeEach(() => {
    (getSystemConfig as any).mockResolvedValue(buildSystemConfig());
    (User.findAll as any).mockResolvedValue([]);
    (SystemConfig.findAll as any).mockResolvedValue([]);
  });

  it('stores an eligible application', async () => {
    (OidcClient.findByPk as any).mockResolvedValue(CLI_CLIENT);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ oidc_cli_client_id: CLI_CLIENT.id });

    expect(res.status).toBe(200);
    expect(SystemConfig.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ key: 'oidc_cli_client_id', value: CLI_CLIENT.id }),
      expect.anything(),
    );
  });

  it.each([
    ['unknown', null],
    ['ineligible', { ...CLI_CLIENT, sessionExchangeEnabled: false }],
  ])('refuses an %s application', async (_name, client) => {
    (OidcClient.findByPk as any).mockResolvedValue(client);

    const res = await request(app)
      .patch('/system-config/admin')
      .send({ oidc_cli_client_id: 'nope' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid OpenID Provider config');
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
  });

  // system_config.value is NOT NULL, so a null is stored as no row at all.
  it('removes the row to clear the key, without looking up an application', async () => {
    const res = await request(app).patch('/system-config/admin').send({ oidc_cli_client_id: null });

    expect(res.status).toBe(200);
    expect(OidcClient.findByPk).not.toHaveBeenCalled();
    expect(SystemConfig.upsert).not.toHaveBeenCalled();
    expect(SystemConfig.destroy).toHaveBeenCalledWith(
      expect.objectContaining({ where: { key: 'oidc_cli_client_id' } }),
    );
  });
});
