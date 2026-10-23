import { randomUUID } from 'crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { getSequelize, initializeModels } from '../../src/models/index.js';
import { TotpCredential } from '../../src/models/totpCredentials.js';
import { User } from '../../src/models/users.js';
import {
  encryptTotpSecret,
  verifyEnabledTotp,
  verifyTotpEnrollment,
} from '../../src/services/totpService.js';
import { hashOtpToken, verifyEmailOTP, verifyPhoneOTP } from '../../src/utils/otp.js';
import { generateTotpCode } from '../../src/utils/totp.js';

const SECRET = 'JBSWY3DPEHPK3PXP';
const CONTENDERS = 5;

async function createUser(values: Partial<User> = {}) {
  const id = randomUUID();
  await User.create({ id, email: `race-${id}@example.com`, roles: ['user'], ...values });
  return id;
}

// Each contender holds its own instance read before any of them writes, which is the
// state two concurrent requests are in once both have passed the comparison.
async function contend<T>(load: () => Promise<T>, run: (loaded: T) => Promise<boolean>) {
  const loaded = await Promise.all(Array.from({ length: CONTENDERS }, load));
  const outcomes = await Promise.all(loaded.map(run));
  return outcomes.filter(Boolean).length;
}

beforeAll(async () => {
  process.env.TOTP_SECRET_ENCRYPTION_KEY = 'postgres-suite-totp-key';
  await initializeModels();
});

afterAll(async () => {
  await getSequelize().close();
});

describe('one-time credentials under concurrent submission', () => {
  it('accepts one valid email OTP exactly once', async () => {
    const id = await createUser({
      emailVerificationToken: hashOtpToken('ABCDEF'),
      emailVerificationTokenExpiry: Date.now() + 60_000,
    });

    const winners = await contend(
      async () => (await User.findByPk(id))!,
      async (user) => (await verifyEmailOTP(user, 'abcdef')).verified,
    );

    expect(winners).toBe(1);
    const stored = await User.findByPk(id);
    expect(stored?.emailVerificationToken).toBeNull();
    expect(stored?.emailVerified).toBe(true);
  });

  it('accepts one valid phone OTP exactly once', async () => {
    const id = await createUser({
      phone: '+14155552671',
      phoneVerificationToken: hashOtpToken('123456'),
      phoneVerificationTokenExpiry: Date.now() + 60_000,
    });

    const winners = await contend(
      async () => (await User.findByPk(id))!,
      async (user) => (await verifyPhoneOTP(user, '123456')).verified,
    );

    expect(winners).toBe(1);
    const stored = await User.findByPk(id);
    expect(stored?.phoneVerificationToken).toBeNull();
    expect(stored?.phoneVerified).toBe(true);
  });

  it('accepts one TOTP code exactly once', async () => {
    const userId = await createUser({ verified: true, emailVerified: true });
    await TotpCredential.create({
      userId,
      ...encryptTotpSecret(SECRET),
      issuer: 'Seamless Auth',
      accountName: `race-${userId}@example.com`,
      enabled: true,
      verifiedAt: new Date(),
      lastUsedAt: null,
      lastUsedCounter: null,
    });
    const code = generateTotpCode({ secret: SECRET });

    const outcomes = await Promise.all(
      Array.from({ length: CONTENDERS }, () => verifyEnabledTotp(userId, code)),
    );

    expect(outcomes.filter((outcome) => outcome.verified)).toHaveLength(1);
  });

  it('enables a pending TOTP credential exactly once', async () => {
    const userId = await createUser({ verified: true, emailVerified: true });
    const totp = (enabled: boolean) =>
      TotpCredential.create({
        userId,
        ...encryptTotpSecret(SECRET),
        issuer: 'Seamless Auth',
        accountName: `race-${userId}@example.com`,
        enabled,
        verifiedAt: enabled ? new Date() : null,
        lastUsedAt: null,
        lastUsedCounter: null,
      });
    const previous = await totp(true);
    const pending = await totp(false);
    const code = generateTotpCode({ secret: SECRET });

    const outcomes = await Promise.allSettled(
      Array.from({ length: CONTENDERS }, () => verifyTotpEnrollment(userId, code)),
    );

    const verified = outcomes.filter(
      (outcome) => outcome.status === 'fulfilled' && outcome.value.verified,
    );
    expect(verified).toHaveLength(1);
    expect(outcomes.every((outcome) => outcome.status === 'fulfilled')).toBe(true);
    await expect(TotpCredential.findByPk(previous.id)).resolves.toMatchObject({ enabled: false });
    await expect(TotpCredential.findByPk(pending.id)).resolves.toMatchObject({ enabled: true });
  });
});
