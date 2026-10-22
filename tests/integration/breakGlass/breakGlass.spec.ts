import { isoCBOR } from '@simplewebauthn/server/helpers';
import { Application } from 'express';
import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

let currentUser: any;

vi.mock('../../../src/middleware/attachAuthMiddleware.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../../src/middleware/attachAuthMiddleware.js')>();

  return {
    ...actual,
    attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
      req.user = currentUser;
      req.sessionId = 'session-1';
      req.attemptId = 'attempt-1';
      next();
    },
  };
});

vi.mock('../../../src/services/metadataServiceBootstrap.js', () => ({
  hasMetadataStatement: vi.fn(async () => false),
  ensureMetadataServiceReady: vi.fn(async () => true),
}));

import { createApp } from '../../../src/app.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import {
  createRefreshTokenLookup,
  generateRefreshToken,
  signAccessToken,
  signEphemeralToken,
} from '../../../src/lib/token.js';
import { AuthFailure } from '../../../src/models/authFailures.js';
import { Credential } from '../../../src/models/credentials.js';
import { RecoveryCode } from '../../../src/models/recoveryCodes.js';
import { Session } from '../../../src/models/sessions.js';
import { TotpCredential } from '../../../src/models/totpCredentials.js';
import { User } from '../../../src/models/users.js';
import { WebAuthnChallenge } from '../../../src/models/webauthnChallenges.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import { sendNoticeEmail } from '../../../src/services/messagingService.js';
import { encryptTotpSecret } from '../../../src/services/totpService.js';
import { generateEmailOTP, verifyEmailOTP } from '../../../src/utils/otp.js';
import { generateTotpCode } from '../../../src/utils/totp.js';
import { buildCredential } from '../../factories/credentialFactory.js';
import { buildSystemConfig } from '../../factories/systemConfigFactory.js';
import { buildTotpCredential } from '../../factories/totpCredentialFactory.js';
import { buildUser } from '../../factories/userFactory.js';
import { buildWebAuthnChallenge } from '../../factories/webauthnChallengeFactory.js';

let app: Application;

const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

function account(overrides: Record<string, unknown>) {
  return buildUser({
    verified: true,
    revoked: false,
    emailVerificationToken: 'hashed',
    emailVerificationTokenExpiry: new Date(Date.now() + 100_000),
    ...overrides,
  });
}

const admin = () => account({ id: 'admin-1', email: 'root@example.com', roles: ['admin:write'] });
const listedNonAdmin = () =>
  account({ id: 'listed-1', email: 'listed@example.com', roles: ['user'] });
const ordinary = () => account({ id: 'user-2', email: 'person@example.com', roles: ['user'] });

const AUTHENTICATOR_POLICY = {
  attachment: 'any',
  userVerification: 'required',
  attestation: 'none',
  requireKnownAuthenticator: false,
  syncedPasskeys: 'allow',
  aaguidAllowList: [],
  aaguidDenyList: [],
};

function policy(overrides: Record<string, unknown> = {}) {
  const { authenticator_policy, ...rest } = overrides;

  return buildSystemConfig({
    app_name: 'Acme',
    login_methods: ['passkey', 'email_otp', 'magic_link'],
    refresh_token_ttl: '1h',
    recovery_codes: { enabled: true, requireAtEnrollment: false },
    authenticator_policy: {
      ...AUTHENTICATOR_POLICY,
      ...(authenticator_policy as Record<string, unknown> | undefined),
    },
    ...rest,
  });
}

const PHISHING_RESISTANT_ONLY = { phishing_resistant_only: true };
const PASSKEY_ONLY = { login_methods: ['passkey'], passkey_login_fallback_enabled: false };

function breakGlassEvents() {
  return (AuthEventService.log as any).mock.calls
    .map(([event]: any[]) => event)
    .filter((event: any) => event.type === 'break_glass_sign_in');
}

function withTotp() {
  (TotpCredential.findOne as any).mockResolvedValue(
    buildTotpCredential({ ...encryptTotpSecret(TOTP_SECRET), lastUsedCounter: null }),
  );
}

function totpLogin() {
  return request(app)
    .post('/totp/verify-login')
    .send({ code: generateTotpCode({ secret: TOTP_SECRET }) });
}

async function passkeyAssertionVerifies() {
  const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');

  (verifyAuthenticationResponse as any).mockResolvedValue({
    verified: true,
    authenticationInfo: { newCounter: 1 },
  });
}

function passkeyLogin() {
  return request(app)
    .post('/webauthn/login/finish')
    .send({ assertionResponse: { id: 'cred-1' } });
}

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv('BREAK_GLASS_EMAILS', 'Root@Example.com, listed@example.com');
  process.env.TOTP_SECRET_ENCRYPTION_KEY = 'test-totp-encryption-key';
  process.env.REFRESH_TOKEN_LOOKUP_SECRET = 'lookup-secret';

  currentUser = admin();
  (getSystemConfig as any).mockResolvedValue(policy());
  (Session.create as any).mockResolvedValue({ id: 'session-1' });
  (signAccessToken as any).mockResolvedValue('access-token');
  (signEphemeralToken as any).mockResolvedValue('ephemeral-token');
  (generateRefreshToken as any).mockReturnValue('refresh-token');
  (createRefreshTokenLookup as any).mockReturnValue('refresh-lookup');
  (Credential.count as any).mockResolvedValue(0);
  (Credential.findAll as any).mockResolvedValue([]);
  (Credential.findOne as any).mockResolvedValue(null);
  (TotpCredential.findOne as any).mockResolvedValue(null);
  (WebAuthnChallenge.findOne as any).mockResolvedValue(
    buildWebAuthnChallenge({ userId: 'admin-1' }),
  );
  (User.findAll as any).mockResolvedValue([
    { email: 'root@example.com', roles: ['admin:write'] },
    { email: 'ops@example.com', roles: ['admin'] },
  ]);
});

describe('/login', () => {
  it('offers a break-glass admin its passkey when the policy lists no passkey', async () => {
    (getSystemConfig as any).mockResolvedValue(policy({ login_methods: ['email_otp'] }));
    (User.findOne as any).mockResolvedValue(admin());
    (Credential.findOne as any).mockResolvedValue(buildCredential({ userId: 'admin-1' }));

    const res = await request(app).post('/login').send({ identifier: 'root@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('admin-1');
    expect(res.body.loginMethods).toEqual(['passkey', 'email_otp']);
  });

  // The list is shaped like anyone's so the answer does not single out a privileged
  // account. The weak methods in it are refused at their endpoints.
  it('shapes the list for a break-glass admin like an ordinary account', async () => {
    (User.findOne as any).mockResolvedValue(admin());
    (Credential.findOne as any).mockResolvedValue(buildCredential({ userId: 'admin-1' }));
    const breakGlass = await request(app).post('/login').send({ identifier: 'root@example.com' });

    (User.findOne as any).mockResolvedValue(ordinary());
    (Credential.findOne as any).mockResolvedValue(buildCredential({ userId: 'user-2' }));
    const other = await request(app).post('/login').send({ identifier: 'person@example.com' });

    expect(breakGlass.body.loginMethods).toEqual(other.body.loginMethods);
  });

  it('lets a TOTP-only break-glass admin continue in phishing-resistant-only mode', async () => {
    (getSystemConfig as any).mockResolvedValue(policy(PHISHING_RESISTANT_ONLY));
    (User.findOne as any).mockResolvedValue(admin());
    withTotp();

    const res = await request(app).post('/login').send({ identifier: 'root@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('admin-1');
    // What a decoy under this policy shows, never an empty list only this account produces.
    expect(res.body.loginMethods).toEqual(['passkey']);
  });

  it('lets a break-glass admin with only recovery codes continue while locked', async () => {
    (getSystemConfig as any).mockResolvedValue(
      policy({
        ...PHISHING_RESISTANT_ONLY,
        lockout_policy: { enabled: true, maxFailures: 3, windowSeconds: 900, lockoutSeconds: 900 },
      }),
    );
    (AuthFailure.findAll as any).mockResolvedValue(
      Array.from({ length: 3 }, () => ({ occurredAt: new Date() })),
    );
    (RecoveryCode.findAll as any).mockResolvedValue([{ usedAt: null, createdAt: new Date() }]);
    (User.findOne as any).mockResolvedValue(admin());

    const res = await request(app).post('/login').send({ identifier: 'root@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('admin-1');
    expect(res.body.loginMethods).toEqual(['passkey']);
  });

  it('answers an ordinary TOTP-only account in that mode with a decoy', async () => {
    (getSystemConfig as any).mockResolvedValue(policy(PHISHING_RESISTANT_ONLY));
    (User.findOne as any).mockResolvedValue(ordinary());
    withTotp();

    const res = await request(app).post('/login').send({ identifier: 'person@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.sub).not.toBe('user-2');
  });

  it('answers a listed account without an admin role with a decoy too', async () => {
    (getSystemConfig as any).mockResolvedValue(policy(PHISHING_RESISTANT_ONLY));
    (User.findOne as any).mockResolvedValue(listedNonAdmin());
    withTotp();

    const res = await request(app).post('/login').send({ identifier: 'listed@example.com' });

    expect(res.body.sub).not.toBe('listed-1');
  });

  it('keeps lockout for a break-glass admin with only TOTP', async () => {
    (getSystemConfig as any).mockResolvedValue(
      policy({
        ...PHISHING_RESISTANT_ONLY,
        lockout_policy: { enabled: true, maxFailures: 3, windowSeconds: 900, lockoutSeconds: 900 },
      }),
    );
    (AuthFailure.findAll as any).mockResolvedValue(
      Array.from({ length: 3 }, () => ({ occurredAt: new Date() })),
    );
    (User.findOne as any).mockResolvedValue(admin());
    withTotp();

    const res = await request(app).post('/login').send({ identifier: 'root@example.com' });

    expect(res.status).toBe(423);
  });

  it('still answers a break-glass admin with no strong factor as a decoy', async () => {
    (getSystemConfig as any).mockResolvedValue(policy(PHISHING_RESISTANT_ONLY));
    (User.findOne as any).mockResolvedValue(admin());

    const res = await request(app).post('/login').send({ identifier: 'root@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.sub).not.toBe('admin-1');
  });
});

describe('passkey sign-in', () => {
  beforeEach(async () => {
    await passkeyAssertionVerifies();
    (Credential.findOne as any).mockResolvedValue(
      buildCredential({ userId: 'admin-1', update: vi.fn() }),
    );
  });

  it.each([
    ['phishing-resistant only', PHISHING_RESISTANT_ONLY],
    ['passkey only', PASSKEY_ONLY],
  ])('signs a break-glass admin in under %s without announcing it', async (_name, config) => {
    (getSystemConfig as any).mockResolvedValue(policy(config));

    const res = await passkeyLogin();

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('admin-1');
    expect(breakGlassEvents()).toEqual([]);
    expect(sendNoticeEmail).not.toHaveBeenCalled();
  });

  it('audits and announces a passkey sign-in the method list would have refused', async () => {
    (getSystemConfig as any).mockResolvedValue(policy({ login_methods: ['email_otp'] }));

    const res = await passkeyLogin();

    expect(res.status).toBe(200);
    expect(breakGlassEvents()).toEqual([
      expect.objectContaining({
        userId: 'admin-1',
        metadata: {
          severity: 'high',
          factor: 'passkey',
          waived: ['login_methods'],
          notices: { sent: 2, failed: 0 },
        },
      }),
    ]);
    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'ops@example.com',
      'Break-glass sign-in on Acme',
      expect.stringContaining('root@example.com'),
    );
  });
});

describe('TOTP sign-in', () => {
  beforeEach(() => {
    withTotp();
  });

  it.each([
    ['phishing-resistant only', PHISHING_RESISTANT_ONLY, 'phishing_resistant_only'],
    ['passkey only', PASSKEY_ONLY, 'passkey_required'],
  ])('signs a break-glass admin in under %s and announces it', async (_name, config, waiver) => {
    (getSystemConfig as any).mockResolvedValue(policy(config));
    (Credential.count as any).mockResolvedValue(1);

    const res = await totpLogin();

    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('admin-1');
    expect(breakGlassEvents()).toEqual([
      expect.objectContaining({
        metadata: expect.objectContaining({ severity: 'high', factor: 'totp', waived: [waiver] }),
      }),
    ]);
    expect(sendNoticeEmail).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['an ordinary user', ordinary],
    ['a listed account without an admin role', listedNonAdmin],
  ])('refuses %s under the same policy', async (_name, build) => {
    currentUser = build();
    (getSystemConfig as any).mockResolvedValue(policy(PHISHING_RESISTANT_ONLY));

    const res = await totpLogin();

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'login_method_disabled' });
    expect(Session.create).not.toHaveBeenCalled();
    expect(breakGlassEvents()).toEqual([]);
  });

  it('keeps lockout for a break-glass admin', async () => {
    (getSystemConfig as any).mockResolvedValue(
      policy({
        ...PHISHING_RESISTANT_ONLY,
        lockout_policy: { enabled: true, maxFailures: 3, windowSeconds: 900, lockoutSeconds: 900 },
      }),
    );
    (AuthFailure.findAll as any).mockResolvedValue(
      Array.from({ length: 3 }, () => ({ occurredAt: new Date() })),
    );

    const res = await totpLogin();

    expect(res.status).toBe(423);
    expect(Session.create).not.toHaveBeenCalled();
  });

  it('does not announce a TOTP sign-in the policy allowed anyway', async () => {
    const res = await totpLogin();

    expect(res.status).toBe(200);
    expect(breakGlassEvents()).toEqual([]);
  });
});

describe('recovery code sign-in', () => {
  const disabled = { recovery_codes: { enabled: false, requireAtEnrollment: false } };

  it('lets a break-glass admin redeem a code while codes are disabled, and announces it', async () => {
    (getSystemConfig as any).mockResolvedValue(policy(disabled));

    const res = await request(app).post('/recovery-codes/redeem').send({ code: 'ABCDE-FGHJK' });

    expect(res.status).toBe(200);
    expect(res.body.recovery).toBe(true);
    expect(breakGlassEvents()).toEqual([
      expect.objectContaining({
        metadata: expect.objectContaining({
          factor: 'recovery_code',
          waived: ['recovery_codes_disabled'],
        }),
      }),
    ]);
  });

  it('refuses an ordinary user while codes are disabled', async () => {
    currentUser = ordinary();
    (getSystemConfig as any).mockResolvedValue(policy(disabled));

    const res = await request(app).post('/recovery-codes/redeem').send({ code: 'ABCDE-FGHJK' });

    expect(res.status).toBe(403);
    expect(RecoveryCode.update).not.toHaveBeenCalled();
  });

  it('lets a break-glass admin make a set while codes are disabled', async () => {
    (getSystemConfig as any).mockResolvedValue(policy(disabled));

    const res = await request(app).post('/recovery-codes');

    expect(res.status).toBe(201);
  });
});

describe('factors that prove only an address', () => {
  it('refuses email OTP for a break-glass admin even though it is enabled', async () => {
    const res = await request(app)
      .post('/otp/verify-login-email-otp')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'login_method_disabled' });
    expect(verifyEmailOTP).not.toHaveBeenCalled();
    expect(Session.create).not.toHaveBeenCalled();
  });

  it('does not send a break-glass admin an email OTP', async () => {
    const res = await request(app).get('/otp/generate-login-email-otp');

    expect(res.status).toBe(403);
    expect(generateEmailOTP).not.toHaveBeenCalled();
  });

  it('refuses the registration email check as a way in for a verified break-glass admin', async () => {
    const res = await request(app)
      .post('/otp/verify-email-otp')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(403);
    expect(verifyEmailOTP).not.toHaveBeenCalled();
  });

  it('refuses a magic link for a break-glass admin', async () => {
    const res = await request(app).get('/magic-link');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'login_method_disabled' });
  });

  it('still signs an ordinary user in with email OTP under the same policy', async () => {
    currentUser = ordinary();
    (verifyEmailOTP as any).mockResolvedValue({ user: currentUser, verified: true });

    const res = await request(app)
      .post('/otp/verify-login-email-otp')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(200);
    expect(Session.create).toHaveBeenCalled();
  });

  it('signs a listed account without an admin role in with email OTP like anyone else', async () => {
    currentUser = listedNonAdmin();
    (verifyEmailOTP as any).mockResolvedValue({ user: currentUser, verified: true });

    const res = await request(app)
      .post('/otp/verify-login-email-otp')
      .send({ verificationToken: '123456' });

    expect(res.status).toBe(200);
  });
});

describe('passkey enrollment', () => {
  const NONE_ATTESTATION = isoCBOR.encode(
    new Map<string, unknown>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', new Uint8Array([1, 2, 3])],
    ]) as never,
  );

  async function syncedPasskeyVerifies() {
    const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

    (verifyRegistrationResponse as any).mockResolvedValue({
      verified: true,
      registrationInfo: {
        fmt: 'none',
        aaguid: '00000000-0000-0000-0000-000000000000',
        attestationObject: NONE_ATTESTATION,
        credential: { id: 'cred-1', publicKey: Buffer.from('key'), counter: 0, transports: [] },
        credentialBackedUp: true,
        credentialDeviceType: 'multiDevice',
      },
    });
  }

  function register() {
    return request(app)
      .post('/webauthn/register/finish')
      .send({ attestationResponse: {}, metadata: {} });
  }

  beforeEach(async () => {
    await syncedPasskeyVerifies();
    (getSystemConfig as any).mockResolvedValue(
      policy({ ...PHISHING_RESISTANT_ONLY, authenticator_policy: { syncedPasskeys: 'block' } }),
    );
    (Credential.create as any).mockResolvedValue({ createdAt: new Date() });
    (WebAuthnChallenge.findOne as any).mockResolvedValue(
      buildWebAuthnChallenge({ purpose: 'registration' }),
    );
  });

  it('enrolls the passkey a break-glass admin has, outside the authenticator policy', async () => {
    (User.findOne as any).mockResolvedValue(admin());

    const res = await register();

    expect(res.status).toBe(200);
    expect(Credential.create).toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'registration_success',
        metadata: expect.objectContaining({
          severity: 'high',
          breakGlassWaived: ['authenticator_policy'],
        }),
      }),
    );
  });

  it('refuses the same passkey for an ordinary user', async () => {
    (User.findOne as any).mockResolvedValue(ordinary());

    const res = await register();

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'synced_passkey_not_allowed' });
    expect(Credential.create).not.toHaveBeenCalled();
  });

  it('lets a break-glass admin ask for an attachment the policy does not pin', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    (generateRegistrationOptions as any).mockResolvedValue({ challenge: 'challenge' });
    (getSystemConfig as any).mockResolvedValue(
      policy({ authenticator_policy: { attachment: 'cross-platform' } }),
    );

    const allowed = await request(app).get('/webauthn/register/start?attachment=platform');

    currentUser = ordinary();
    const refused = await request(app).get('/webauthn/register/start?attachment=platform');

    expect(allowed.status).toBe(200);
    expect(refused.status).toBe(400);
  });
});
