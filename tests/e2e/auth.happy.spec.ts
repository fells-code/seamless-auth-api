import request from 'supertest';
import { describe, it, expect, beforeAll, vi, afterAll } from 'vitest';

vi.unmock('../../src/models/authEvents.js');
vi.unmock('../../src/models/sessions.js');
vi.unmock('../../src/models/users.js');
vi.unmock('../../src/models/systemConfig.js');
vi.unmock('../../src/models/credentials.js');
vi.unmock('../../src/models/magicLinks.js');
vi.unmock('../../src/services/sessionService.js');
vi.unmock('../../src/services/authEventService.js');
vi.unmock('../../src/models');
vi.unmock('../../src/services/messagingService.js');
vi.unmock('../../src/lib/cookie.js');
vi.unmock('../../src/lib/token.js');
vi.unmock('../../src/middleware/attachAuthMiddleware.js');
vi.unmock('../../src/middleware/verifyCookieAuth.js');

vi.unmock('../../src/config/getSystemConfig.js');
vi.unmock('../../src/utils/utils.js');
vi.unmock('../../src/utils/otp.js');
vi.unmock('../../src/utils/token.js');
vi.unmock('../../src/utils/cookie.js');
vi.unmock('../../src/utils/secretStore.js');

vi.unmock('bcrypt-ts');

let app: any;
const shouldRunE2E = process.env.CI !== 'true' && process.env.TEST_DB === 'postgres';

beforeAll(async () => {
  if (!shouldRunE2E) {
    return;
  }

  vi.stubEnv('NODE_ENV', 'test');
  vi.stubEnv('AUTH_MODE', 'web');

  vi.stubEnv('DB_DIALECT', 'postgres');
  vi.stubEnv('DB_HOST', 'localhost');
  vi.stubEnv('DB_PORT', '5432');
  vi.stubEnv('DB_NAME', 'seamless_auth_test');
  vi.stubEnv('DB_USER', 'myuser');
  vi.stubEnv('DB_PASSWORD', 'mypassword');

  vi.stubEnv('ISSUER', 'test-issuer');
  vi.stubEnv('APP_ID', 'test-app');

  vi.stubEnv('JWKS_ACTIVE_KIDe', 'dev-main');
  vi.stubEnv('API_SERVICE_TOKEN', 'service-token');

  vi.stubEnv('DEFAULT_ROLES', 'user');
  vi.stubEnv('AVAILABLE_ROLES', 'user,admin');
  vi.stubEnv('ACCESS_TOKEN_TTL', '15m');
  vi.stubEnv('REFRESH_TOKEN_TTL', '1h');
  vi.stubEnv('RATE_LIMIT', '100');
  vi.stubEnv('DELAY_AFTER', '50');
  vi.stubEnv('RPID', 'localhost');
  vi.stubEnv('ORIGINS', 'http://localhost');
  vi.stubEnv('APP_NAME', 'TestApp');

  const { initializeModels } = await import('../../src/models');
  const models = await initializeModels();

  await models.sequelize.sync({ force: true });

  const { bootstrapSystemConfig } = await import('../../src/config/bootstrapSystemConfig');
  await bootstrapSystemConfig();

  const { createApp } = await import('../../src/app');
  app = await createApp();
});

afterAll(() => {
  vi.unstubAllEnvs();
});

(shouldRunE2E ? it : it.skip)('full auth lifecycle works', async () => {
  const email = 'test@example.com';
  const phone = '+14155552671';

  const registerRes = await request(app).post('/registration/register').send({ email, phone });

  expect(registerRes.status).toBe(200);

  const cookies = registerRes.headers['set-cookie'];
  expect(cookies).toBeDefined();

  const otpRes = await request(app).get('/otp/generate-phone-otp').set('Cookie', cookies);

  expect(otpRes.status).toBe(200);

  const { User } = await import('../../src/models/users');

  const user = await User.findOne({ where: { email } });

  expect(user).toBeDefined();
  const otp = user?.phoneVerificationToken;

  expect(otp).toBeDefined();

  const verifyRes = await request(app)
    .post('/otp/verify-phone-otp')
    .set('Cookie', cookies)
    .send({ verificationToken: otp });

  expect(verifyRes.status).toBe(200);

  const emailOtpRes = await request(app).get('/otp/generate-email-otp').set('Cookie', cookies);

  expect(emailOtpRes.status).toBe(200);

  await user?.reload();
  const emailOtp = user?.emailVerificationToken;

  expect(emailOtp).toBeDefined();

  const emailVerifyRes = await request(app)
    .post('/otp/verify-email-otp')
    .set('Cookie', cookies)
    .send({ verificationToken: emailOtp });

  expect(emailVerifyRes.status).toBe(200);

  let authCookies = emailVerifyRes.headers['set-cookie'];
  expect(authCookies).toBeDefined();

  const meRes = await request(app).get('/users/me').set('Cookie', authCookies);

  const maybeNewCookies = meRes.headers['set-cookie'];
  if (maybeNewCookies) {
    authCookies = maybeNewCookies;
  }

  expect(meRes.status).toBe(200);
  expect(Array.isArray(meRes.body.user)).toBeDefined();

  const brokenCookies = (authCookies as unknown as string[]).filter(
    (c: string) => !c.includes('seamless_access'),
  );

  expect(brokenCookies.some((c) => c.includes('seamless_refresh'))).toBe(true);

  const refreshRes = await request(app).get('/users/me').set('Cookie', brokenCookies);

  expect(refreshRes.status).toBe(200);

  const refreshedCookies = refreshRes.headers['set-cookie'];
  expect(refreshedCookies).toBeDefined();

  authCookies = refreshedCookies;

  const logoutRes = await request(app).get('/logout').set('Cookie', authCookies);

  expect(logoutRes.status).toBe(200);
});
