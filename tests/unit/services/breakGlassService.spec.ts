import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { Credential } from '../../../src/models/credentials.js';
import { RecoveryCode } from '../../../src/models/recoveryCodes.js';
import { TotpCredential } from '../../../src/models/totpCredentials.js';
import { User } from '../../../src/models/users.js';
import { AuthEventService } from '../../../src/services/authEventService.js';
import {
  breakGlassWaivers,
  hasBreakGlassCodeFactor,
  recordBreakGlassSignIn,
  rejectWeakFactorForBreakGlass,
  warnOnBreakGlassMisconfiguration,
} from '../../../src/services/breakGlassService.js';
import { DeliveryError } from '../../../src/services/deliveryError.js';
import { sendNoticeEmail } from '../../../src/services/messagingService.js';
import getLogger from '../../../src/utils/logger.js';

const logger = getLogger('breakGlass');
const req = { ip: '127.0.0.1', headers: {} } as any;

function mockRes() {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv('BREAK_GLASS_EMAILS', 'root@example.com');
  vi.spyOn(logger, 'warn');
  vi.spyOn(logger, 'info');
  vi.spyOn(logger, 'error');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('warnOnBreakGlassMisconfiguration', () => {
  const env = { BREAK_GLASS_EMAILS: 'root@example.com,nobody@example.com,user@example.com' };

  it('does nothing when no address is listed', async () => {
    await warnOnBreakGlassMisconfiguration({});

    expect(User.findAll).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('warns with a count of listed entries that are not admin accounts, never the addresses', async () => {
    (User.findAll as any).mockResolvedValue([
      { email: 'root@example.com', roles: ['admin:write'], revoked: false },
      { email: 'user@example.com', roles: ['user'], revoked: false },
    ]);

    await warnOnBreakGlassMisconfiguration(env);

    expect(logger.warn).toHaveBeenCalledTimes(1);
    const message = (logger.warn as any).mock.calls[0][0] as string;
    expect(message).toContain('2 of 3 BREAK_GLASS_EMAILS entries are not admin accounts');
    expect(message).not.toContain('@');
  });

  it('reports a clean configuration without addresses', async () => {
    (User.findAll as any).mockResolvedValue([
      { email: 'root@example.com', roles: ['admin'], revoked: false },
    ]);

    await warnOnBreakGlassMisconfiguration({ BREAK_GLASS_EMAILS: 'root@example.com' });

    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledWith('Break-glass configured for 1 admin account(s)');
  });
});

describe('breakGlassWaivers', () => {
  it('names login_methods for a passkey sign-in the method list leaves out', async () => {
    (getSystemConfig as any).mockResolvedValue({ login_methods: ['email_otp'] });

    expect(await breakGlassWaivers('passkey', 'user-1')).toEqual(['login_methods']);
  });

  it('waives nothing for a passkey the policy already allows', async () => {
    (getSystemConfig as any).mockResolvedValue({ phishing_resistant_only: true });

    expect(await breakGlassWaivers('passkey', 'user-1')).toEqual([]);
  });

  it('names phishing_resistant_only for TOTP in that mode', async () => {
    (getSystemConfig as any).mockResolvedValue({ phishing_resistant_only: true });

    expect(await breakGlassWaivers('totp', 'user-1')).toEqual(['phishing_resistant_only']);
  });

  it('names passkey_required for TOTP on an account whose passkey has no fallback', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey', 'email_otp'],
      passkey_login_fallback_enabled: false,
    });
    (Credential.count as any).mockResolvedValue(1);

    expect(await breakGlassWaivers('totp', 'user-1')).toEqual(['passkey_required']);
  });

  it('waives nothing for TOTP when fallback is allowed', async () => {
    (getSystemConfig as any).mockResolvedValue({
      login_methods: ['passkey', 'email_otp'],
      passkey_login_fallback_enabled: true,
    });

    expect(await breakGlassWaivers('totp', 'user-1')).toEqual([]);
  });

  it('names recovery_codes_disabled for a code redeemed while codes are off', async () => {
    (getSystemConfig as any).mockResolvedValue({ recovery_codes: { enabled: false } });
    expect(await breakGlassWaivers('recovery_code', 'user-1')).toEqual(['recovery_codes_disabled']);

    (getSystemConfig as any).mockResolvedValue({ recovery_codes: { enabled: true } });
    expect(await breakGlassWaivers('recovery_code', 'user-1')).toEqual([]);
  });
});

describe('hasBreakGlassCodeFactor', () => {
  it('counts an unspent recovery code, even while locked', async () => {
    (RecoveryCode.findAll as any).mockResolvedValue([{ usedAt: null, createdAt: new Date() }]);

    expect(await hasBreakGlassCodeFactor('user-1', true)).toBe(true);
  });

  it('counts TOTP only while the account is not locked', async () => {
    (RecoveryCode.findAll as any).mockResolvedValue([]);
    (TotpCredential.findOne as any).mockResolvedValue({ enabled: true });

    expect(await hasBreakGlassCodeFactor('user-1', false)).toBe(true);
    expect(await hasBreakGlassCodeFactor('user-1', true)).toBe(false);
  });
});

describe('recordBreakGlassSignIn', () => {
  const user = { id: 'user-1', email: 'root@example.com' };

  it('records nothing for a sign-in that relied on no exemption', async () => {
    await recordBreakGlassSignIn({ req, user, factor: 'passkey', waived: [] });

    expect(AuthEventService.log).not.toHaveBeenCalled();
    expect(sendNoticeEmail).not.toHaveBeenCalled();
  });

  it('notices every verified admin and logs a high severity event', async () => {
    (getSystemConfig as any).mockResolvedValue({ app_name: 'Acme' });
    (User.findAll as any).mockResolvedValue([
      { email: 'root@example.com', roles: ['admin:write'] },
      { email: 'reader@example.com', roles: ['admin:read'] },
      { email: 'scoped@example.com', roles: ['admin:users:read'] },
    ]);
    (sendNoticeEmail as any)
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new DeliveryError('down', null));

    await recordBreakGlassSignIn({
      req,
      user,
      factor: 'recovery_code',
      waived: ['recovery_codes_disabled'],
    });

    expect(User.findAll).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ revoked: false, emailVerified: true }),
      }),
    );
    expect(sendNoticeEmail).toHaveBeenCalledTimes(2);
    expect(sendNoticeEmail).toHaveBeenCalledWith(
      'reader@example.com',
      'Break-glass sign-in on Acme',
      expect.stringContaining('root@example.com signed in to Acme with recovery code'),
    );
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'break_glass_sign_in',
        metadata: {
          severity: 'high',
          factor: 'recovery_code',
          waived: ['recovery_codes_disabled'],
          notices: { sent: 1, failed: 1 },
        },
      }),
    );
  });

  it('still logs the event when the recipients cannot be read', async () => {
    (getSystemConfig as any).mockResolvedValue(null);
    (User.findAll as any).mockRejectedValue(new Error('db down'));

    await recordBreakGlassSignIn({ req, user, factor: 'totp', waived: ['passkey_required'] });

    expect(logger.error).toHaveBeenCalled();
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'break_glass_sign_in',
        metadata: expect.objectContaining({ notices: { sent: 0, failed: 0 } }),
      }),
    );
  });
});

describe('rejectWeakFactorForBreakGlass', () => {
  it('refuses a listed admin', async () => {
    const res = mockRes();

    const refused = await rejectWeakFactorForBreakGlass(
      { id: 'user-1', email: 'root@example.com', roles: ['admin'] },
      'email_otp',
      req,
      res,
    );

    expect(refused).toBe(true);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'login_method_disabled' });
    expect(AuthEventService.log).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'login_failed',
        metadata: { reason: 'Break-glass account requires a strong factor', method: 'email_otp' },
      }),
    );
  });

  it('leaves anyone else to the ordinary policy', async () => {
    const res = mockRes();

    expect(
      await rejectWeakFactorForBreakGlass(
        { email: 'root@example.com', roles: ['user'] },
        'email_otp',
        req,
        res,
      ),
    ).toBe(false);
    expect(res.status).not.toHaveBeenCalled();
  });
});
