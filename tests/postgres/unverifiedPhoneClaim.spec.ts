import fs from 'fs';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { invalidateSystemConfigCache } from '../../src/config/getSystemConfig.js';
import { getSequelize, initializeModels } from '../../src/models/index.js';
import { SystemConfig } from '../../src/models/systemConfig.js';
import { User } from '../../src/models/users.js';
import { buildSystemConfig } from '../factories/systemConfigFactory.js';

const EXTERNAL = { 'x-seamless-auth-delivery-mode': 'external' };

let app: Awaited<ReturnType<typeof import('../../src/app.js').createApp>>;
let storedLoginMethods: unknown;

function codeFrom(res: request.Response) {
  return String(res.body.delivery?.token);
}

beforeAll(async () => {
  vi.stubEnv('ISSUER', 'http://localhost:5312');
  vi.stubEnv('ALLOW_UNCREDENTIALED_DELIVERY_SECRETS', 'true');
  vi.stubEnv('DISABLE_AUTH_RATE_LIMITS', 'true');
  vi.stubEnv('SEAMLESS_DEV_KEYS_DIR', fs.mkdtempSync(path.join(os.tmpdir(), 'seamless-keys-')));

  await initializeModels();

  for (const [key, value] of Object.entries(buildSystemConfig())) {
    await getSequelize().query(
      `INSERT INTO system_config (key, value, "createdAt", "updatedAt")
       VALUES (:key, :value, now(), now())
       ON CONFLICT (key) DO NOTHING`,
      { replacements: { key, value: JSON.stringify(value) } },
    );
  }

  storedLoginMethods = (await SystemConfig.findByPk('login_methods'))?.value;
  await SystemConfig.update(
    { value: ['passkey', 'magic_link', 'email_otp', 'phone_otp'] },
    { where: { key: 'login_methods' } },
  );
  invalidateSystemConfigCache();

  const { initDevSigningKey } = await import('../../src/utils/signingKeyStore.js');
  const { createApp } = await import('../../src/app.js');
  initDevSigningKey();
  app = await createApp();
});

afterAll(async () => {
  // Every file shares the one database, and phone is unique.
  await getSequelize().query(`DELETE FROM users WHERE email LIKE :pattern`, {
    replacements: { pattern: '%@unverified-phone.test' },
  });
  await SystemConfig.update({ value: storedLoginMethods }, { where: { key: 'login_methods' } });
  invalidateSystemConfigCache();
  vi.unstubAllEnvs();
  await getSequelize().close();
});

/** Registers `email` with `phone` attached, then has the owner claim it by email code. */
async function plantPhoneThenClaim(email: string, phone: string) {
  const planted = await request(app)
    .post('/registration/register')
    .set(EXTERNAL)
    .send({ email, phone });
  expect(planted.status).toBe(200);

  const owner = await request(app).post('/registration/register').set(EXTERNAL).send({ email });
  expect(owner.status).toBe(200);

  const claimed = await request(app)
    .post('/otp/verify-email-otp')
    .set('Authorization', `Bearer ${owner.body.token}`)
    .send({ verificationToken: codeFrom(owner) });
  expect(claimed.status).toBe(200);

  const user = await User.findOne({ where: { email } });
  expect(user).toEqual(expect.objectContaining({ verified: true, phone, phoneVerified: false }));

  return { user: user! };
}

// Whoever registers an address first can attach a phone to the account it creates. The
// owner later claims the account by proving the address, and the phone, never verified,
// stays on it. It must not become a way into the owner's account.
describe('a phone planted before the owner claims the account', () => {
  it('does not sign in by phone OTP', async () => {
    const phone = '+14155552681';
    const { user } = await plantPhoneThenClaim('planted-login@unverified-phone.test', phone);

    const login = await request(app).post('/login').send({ identifier: phone });
    expect(login.status).toBe(200);
    expect(login.body.sub).not.toBe(user.id);

    const byEmail = await request(app)
      .post('/login')
      .send({ identifier: 'planted-login@unverified-phone.test' });
    expect(byEmail.body.sub).toBe(user.id);
    expect(byEmail.body.loginMethods).not.toContain('phone_otp');

    const send = await request(app)
      .get('/otp/generate-login-phone-otp')
      .set(EXTERNAL)
      .set('Authorization', `Bearer ${byEmail.body.token}`);
    expect(send.status).toBe(400);

    await user.reload();
    expect(user.phoneVerificationToken).toBeNull();
  });

  it('does not accept a code sent before the claim', async () => {
    const email = 'planted-early@unverified-phone.test';
    const planted = await request(app)
      .post('/registration/register')
      .set(EXTERNAL)
      .send({ email, phone: '+14155552682' });

    // Sent while the account is still unclaimed, so it really goes to the planted phone.
    const early = await request(app)
      .get('/otp/generate-phone-otp')
      .set(EXTERNAL)
      .set('Authorization', `Bearer ${planted.body.token}`);
    expect(early.body.delivery?.kind).toBe('otp_sms');

    const owner = await request(app).post('/registration/register').set(EXTERNAL).send({ email });
    await request(app)
      .post('/otp/verify-email-otp')
      .set('Authorization', `Bearer ${owner.body.token}`)
      .send({ verificationToken: codeFrom(owner) });

    const byEmail = await request(app).post('/login').send({ identifier: email });

    for (const [route, token] of [
      ['/otp/verify-login-phone-otp', byEmail.body.token],
      ['/otp/verify-phone-otp', byEmail.body.token],
      ['/otp/verify-phone-otp', planted.body.token],
    ]) {
      const verify = await request(app)
        .post(route)
        .set('Authorization', `Bearer ${token}`)
        .send({ verificationToken: codeFrom(early) });
      expect(verify.status).toBe(401);
      expect(verify.body.token).toBeUndefined();
    }

    const user = await User.findOne({ where: { email } });
    expect(user).toEqual(expect.objectContaining({ verified: true, phoneVerified: false }));
  });

  it('cannot be verified through registration once the account is claimed', async () => {
    const phone = '+14155552683';
    const { user } = await plantPhoneThenClaim('planted-verify@unverified-phone.test', phone);

    const again = await request(app)
      .post('/registration/register')
      .set(EXTERNAL)
      .send({ email: 'planted-verify@unverified-phone.test' });

    const send = await request(app)
      .get('/otp/generate-phone-otp')
      .set(EXTERNAL)
      .set('Authorization', `Bearer ${again.body.token}`);
    expect(send.status).toBe(200);
    expect(send.body.delivery).toBeUndefined();

    await user.reload();
    expect(user.phoneVerificationToken).toBeNull();
    expect(user.phoneVerified).toBe(false);
  });
});

describe('phone-first sign up', () => {
  it('still signs in by phone OTP', async () => {
    const email = 'phone-first@unverified-phone.test';
    const phone = '+14155552684';

    const registered = await request(app)
      .post('/registration/register')
      .set(EXTERNAL)
      .send({ email, phone });
    const token = registered.body.token;

    const sms = await request(app)
      .get('/otp/generate-phone-otp')
      .set(EXTERNAL)
      .set('Authorization', `Bearer ${token}`);
    const phoneVerified = await request(app)
      .post('/otp/verify-phone-otp')
      .set('Authorization', `Bearer ${token}`)
      .send({ verificationToken: codeFrom(sms) });
    expect(phoneVerified.status).toBe(200);

    const emailVerified = await request(app)
      .post('/otp/verify-email-otp')
      .set('Authorization', `Bearer ${token}`)
      .send({ verificationToken: codeFrom(registered) });
    expect(emailVerified.status).toBe(200);

    const login = await request(app).post('/login').send({ identifier: phone });
    expect(login.body.loginMethods).toContain('phone_otp');

    const send = await request(app)
      .get('/otp/generate-login-phone-otp')
      .set(EXTERNAL)
      .set('Authorization', `Bearer ${login.body.token}`);
    const signedIn = await request(app)
      .post('/otp/verify-login-phone-otp')
      .set('Authorization', `Bearer ${login.body.token}`)
      .send({ verificationToken: codeFrom(send) });

    expect(signedIn.status).toBe(200);
    expect(signedIn.body.email).toBe(email);
  });
});
