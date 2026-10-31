import { generateKeyPairSync } from 'crypto';
import { Application } from 'express';
import { SignJWT } from 'jose';
import request from 'supertest';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/models/oidcClients.js', () => ({
  OidcClient: { findByPk: vi.fn() },
}));

vi.mock('../../../src/models/oidcPayloads.js', () => ({
  OidcPayload: { findOne: vi.fn() },
}));

import { createApp } from '../../../src/app';
import { getSystemConfig } from '../../../src/config/getSystemConfig';
import { OidcClient } from '../../../src/models/oidcClients.js';
import { OidcPayload } from '../../../src/models/oidcPayloads.js';
import { User } from '../../../src/models/users.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { sendNoticeEmail, sendNoticeSms } from '../../../src/services/messagingService.js';
import { __resetOidcProviderKeyCache } from '../../../src/services/oidcProviderKeys';
import { mintInternalServiceToken } from '../../factories/serviceTokenFactory';
import { buildSystemConfig } from '../../factories/systemConfigFactory';
import { buildUser } from '../../factories/userFactory';

const ISSUER = 'https://login.example.com';
const RESOURCE = `${ISSUER}/seamless`;
const USER = '3f0c1d2e-4b5a-4c6d-8e7f-9a0b1c2d3e4f';
const PATH = '/applications/account-notices';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateJwk = { ...privateKey.export({ format: 'jwk' }), kid: 'k1' };
const { privateKey: strangerKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

let app: Application;

function client(overrides: Record<string, unknown> = {}) {
  return {
    id: 'locksley',
    name: 'Locksley',
    grantTypes: ['authorization_code', 'client_credentials'],
    redirectUris: ['https://app.locksley.example/callback', 'http://127.0.0.1/callback'],
    noticesEnabled: true,
    disabledAt: null,
    ...overrides,
  };
}

async function token(
  claims: Record<string, unknown> = {},
  { key = privateKey, typ = 'at+jwt' }: { key?: typeof privateKey; typ?: string } = {},
) {
  return new SignJWT({
    iss: ISSUER,
    aud: RESOURCE,
    sub: 'locksley',
    client_id: 'locksley',
    scope: 'notices:send',
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key);
}

const notice = { userId: USER, subject: 'Device recovery started', text: 'A recovery opened.' };

async function send(body: Record<string, unknown> = notice, bearer?: string) {
  return request(app)
    .post(PATH)
    .set('Authorization', `Bearer ${bearer ?? (await token())}`)
    .send(body);
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  __resetOidcProviderKeyCache();
  vi.stubEnv('DISABLE_AUTH_RATE_LIMITS', 'true');
  vi.stubEnv('OIDC_JWKS_ACTIVE_KID', 'k1');
  vi.stubEnv('OIDC_JWKS_KEYS', JSON.stringify({ keys: [privateJwk] }));
  vi.mocked(getSystemConfig).mockResolvedValue(
    buildSystemConfig({ oidc_issuer: ISSUER, app_name: 'Acme ID' }) as never,
  );
  vi.mocked(OidcClient.findByPk).mockResolvedValue(client() as never);
  vi.mocked(OidcPayload.findOne).mockResolvedValue({
    payload: { accountId: USER, clientId: 'locksley' },
  } as never);
  vi.mocked(User.findByPk).mockResolvedValue(buildUser({ id: USER }) as never);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('POST /applications/account-notices', () => {
  it('sends on every verified channel inside the fixed template', async () => {
    const res = await send({ ...notice, actionUrl: 'https://app.locksley.example/devices' });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      channels: [
        { channel: 'email', status: 'sent' },
        { channel: 'sms', status: 'sent' },
      ],
    });
    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'test@example.com',
      '[Locksley] Device recovery started',
      'A recovery opened.\n\nhttps://app.locksley.example/devices\n\n--\nSent by Locksley through Acme ID.',
    );
    expect(sendNoticeSms).toHaveBeenCalledWith('+14155552671', expect.stringContaining('Locksley'));
    expect(JSON.stringify(res.body)).not.toContain('test@example.com');
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'oidc_account_notice_sent',
        userId: USER,
        metadata: expect.objectContaining({ clientId: 'locksley' }),
      }),
    );
  });

  it('only checks a grant held with the asking client', async () => {
    await send();

    expect(OidcPayload.findOne).toHaveBeenCalledWith({
      where: expect.objectContaining({
        model: 'Grant',
        payload: { accountId: USER, clientId: 'locksley' },
      }),
    });
  });

  it('sends only on the channels named', async () => {
    const res = await send({ ...notice, channels: ['sms'] });

    expect(res.body.channels).toEqual([{ channel: 'sms', status: 'sent' }]);
    expect(sendNoticeEmail).not.toHaveBeenCalled();
  });

  it('skips an unverified address', async () => {
    vi.mocked(User.findByPk).mockResolvedValue(
      buildUser({ id: USER, phoneVerified: false }) as never,
    );

    const res = await send();

    expect(res.body.channels).toEqual([{ channel: 'email', status: 'sent' }]);
  });

  it('answers 422 when no named channel is verified', async () => {
    vi.mocked(User.findByPk).mockResolvedValue(
      buildUser({ id: USER, phoneVerified: false }) as never,
    );

    const res = await send({ ...notice, channels: ['sms'] });

    expect(res.status).toBe(422);
    expect(res.body).toEqual({ error: 'notice_no_channel' });
  });

  it('records a failed notice when no channel accepted it', async () => {
    vi.mocked(sendNoticeEmail).mockRejectedValue(
      new (await import('../../../src/services/deliveryError.js')).DeliveryError('down'),
    );

    const res = await send({ ...notice, channels: ['email'] });

    expect(res.status).toBe(200);
    expect(res.body.channels).toEqual([{ channel: 'email', status: 'failed' }]);
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'oidc_account_notice_failed' }),
    );
  });

  it.each([
    [
      'a user with no grant for the client',
      () => vi.mocked(OidcPayload.findOne).mockResolvedValue(null),
    ],
    ['a user that does not exist', () => vi.mocked(User.findByPk).mockResolvedValue(null)],
    [
      'a revoked user',
      () =>
        vi.mocked(User.findByPk).mockResolvedValue(buildUser({ id: USER, revoked: true }) as never),
    ],
  ])('answers the same 404 for %s', async (_label, arrange) => {
    arrange();

    const res = await send();

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'notice_unknown_user' });
    expect(sendNoticeEmail).not.toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'oidc_account_notice_failed' }),
    );
  });

  it.each([
    'https://evil.example/devices',
    'https://app.locksley.example:8443/devices',
    'https://user:pass@app.locksley.example/devices',
  ])('refuses an action link off the registered https origins (%s)', async (actionUrl) => {
    const res = await send({ ...notice, actionUrl });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'notice_action_url_not_allowed' });
    expect(User.findByPk).not.toHaveBeenCalled();
  });

  it('strips line breaks the application name carries out of the subject', async () => {
    vi.mocked(OidcClient.findByPk).mockResolvedValue(
      client({ name: 'Locksley\r\nBcc: x@example.com' }) as never,
    );

    await send({ ...notice, channels: ['email'] });

    expect(vi.mocked(sendNoticeEmail).mock.calls[0][1]).toBe(
      '[Locksley Bcc: x@example.com] Device recovery started',
    );
  });

  it('refuses a subject with a line break', async () => {
    const res = await send({ ...notice, subject: 'Hi\r\nBcc: x@example.com' });

    expect(res.status).toBe(400);
    expect(sendNoticeEmail).not.toHaveBeenCalled();
  });

  describe('external delivery', () => {
    it('returns the deliveries to a caller that owns delivery and accepts the kinds', async () => {
      const serviceToken = await mintInternalServiceToken();

      const res = await request(app)
        .post(PATH)
        .set('Authorization', `Bearer ${await token()}`)
        .set('x-seamless-auth-delivery-mode', 'external')
        .set('x-seamless-service-token', serviceToken)
        .set('x-seamless-auth-delivery-kinds', 'account_notice_email')
        .send(notice);

      expect(res.status).toBe(200);
      expect(res.body.channels).toEqual([
        { channel: 'email', status: 'returned_for_external_delivery' },
        { channel: 'sms', status: 'not_sent_external_delivery' },
      ]);
      expect(res.body.deliveries).toEqual([
        expect.objectContaining({
          kind: 'account_notice_email',
          notice: 'application_notice',
          to: 'test@example.com',
          application: { clientId: 'locksley', name: 'Locksley' },
        }),
      ]);
      expect(sendNoticeEmail).not.toHaveBeenCalled();
    });

    it('sends directly when the caller asks for external delivery without the service token', async () => {
      const res = await request(app)
        .post(PATH)
        .set('Authorization', `Bearer ${await token()}`)
        .set('x-seamless-auth-delivery-mode', 'external')
        .send(notice);

      expect(res.status).toBe(200);
      expect(res.body.deliveries).toBeUndefined();
      expect(sendNoticeEmail).toHaveBeenCalled();
    });
  });

  describe('the application token', () => {
    it('answers 401 without a bearer token', async () => {
      const res = await request(app).post(PATH).send(notice);

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'notice_invalid_token' });
    });

    it.each([
      ['signed by another key', async () => token({}, { key: strangerKey })],
      ['for another audience', async () => token({ aud: 'https://api.example.com' })],
      ['from another issuer', async () => token({ iss: 'https://other.example.com' })],
      ['without the notices scope', async () => token({ scope: 'read' })],
      ['for a user rather than the client', async () => token({ sub: USER })],
      ['without the access token type', async () => token({}, { typ: 'JWT' })],
      ['with a non-string client id', async () => token({ client_id: 7 })],
    ])('refuses a token %s', async (_label, mint) => {
      const res = await send(notice, await mint());

      expect(res.status).toBe(401);
      expect(sendNoticeEmail).not.toHaveBeenCalled();
    });

    it('answers 401 while the provider has no issuer', async () => {
      vi.mocked(getSystemConfig).mockResolvedValue(buildSystemConfig({}) as never);

      expect((await send()).status).toBe(401);
    });

    it('answers 401 for a disabled client', async () => {
      vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ disabledAt: new Date() }) as never);

      expect((await send()).status).toBe(401);
    });

    it('answers 401 for a client no longer allowed client credentials', async () => {
      vi.mocked(OidcClient.findByPk).mockResolvedValue(
        client({ grantTypes: ['authorization_code'] }) as never,
      );

      expect((await send()).status).toBe(401);
    });

    it('answers 403 once an admin turns notices off', async () => {
      vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ noticesEnabled: false }) as never);

      const res = await send();

      expect(res.status).toBe(403);
      expect(res.body).toEqual({ error: 'notice_not_enabled' });
    });
  });

  describe('rate limits', () => {
    beforeEach(() => {
      vi.stubEnv('DISABLE_AUTH_RATE_LIMITS', 'false');
    });

    it('limits notices to one user from one client', async () => {
      const userId = '7d6c5b4a-3e2f-4a1b-9c8d-7e6f5a4b3c2d';
      const bearer = await token();
      const statuses: number[] = [];

      for (let attempt = 0; attempt < 11; attempt += 1) {
        statuses.push((await send({ ...notice, userId }, bearer)).status);
      }

      expect(statuses.slice(0, 10).every((status) => status !== 429)).toBe(true);
      const limited = await send({ ...notice, userId }, bearer);
      expect(limited.status).toBe(429);
      expect(limited.body).toEqual({ error: 'notice_rate_limited' });
    });

    it('limits every notice from one client', async () => {
      vi.mocked(OidcClient.findByPk).mockResolvedValue(client({ id: 'busy' }) as never);
      const bearer = await token({ client_id: 'busy', sub: 'busy' });
      let last = 0;

      for (let attempt = 0; attempt <= 300; attempt += 1) {
        last = (await send({ ...notice, userId: `user-${attempt}` }, bearer)).status;
      }

      expect(last).toBe(429);
    });
  });
});
