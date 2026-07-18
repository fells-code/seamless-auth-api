import { randomBytes } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { TotpCredential } from '../../../src/models/totpCredentials.js';
import {
  decryptTotpSecret,
  disableTotp,
  encryptTotpSecret,
  getTotpStatus,
  startTotpEnrollment,
  verifyEnabledTotp,
  verifyTotpEnrollment,
} from '../../../src/services/totpService.js';
import { generateTotpCode } from '../../../src/utils/totp.js';
import { buildTotpCredential } from '../../factories/totpCredentialFactory.js';

beforeEach(() => {
  vi.clearAllMocks();
  process.env.TOTP_SECRET_ENCRYPTION_KEY = 'test-totp-encryption-key';
});

describe('totpService', () => {
  it('starts enrollment with an encrypted pending credential and setup URI', async () => {
    const result = await startTotpEnrollment({
      userId: 'user-1',
      email: 'test@example.com',
      issuer: 'Seamless Auth',
    });

    expect(result.secret).toMatch(/^[A-Z2-7]+$/);
    expect(result.otpauthUrl).toContain('otpauth://totp/');
    expect(TotpCredential.create).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        secretCiphertext: expect.any(String),
        secretIv: expect.any(String),
        secretTag: expect.any(String),
        enabled: false,
      }),
    );
  });

  it('verifies pending enrollment and enables the credential', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptTotpSecret(secret);
    const credential = buildTotpCredential({
      ...encrypted,
      enabled: false,
      lastUsedCounter: null,
    });
    const code = generateTotpCode({ secret });

    (TotpCredential.findOne as any).mockResolvedValue(credential);

    const result = await verifyTotpEnrollment('user-1', code);

    expect(result.verified).toBe(true);
    expect(TotpCredential.update).toHaveBeenCalledWith(
      { enabled: false },
      { where: { userId: 'user-1', enabled: true } },
    );
    expect(credential.update).toHaveBeenCalledWith(
      expect.objectContaining({
        enabled: true,
        verifiedAt: expect.any(Date),
        lastUsedAt: expect.any(Date),
        lastUsedCounter: expect.any(Number),
      }),
    );
  });

  it('rejects reused TOTP counters', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptTotpSecret(secret);
    const code = generateTotpCode({ secret });
    const firstCredential = buildTotpCredential({
      ...encrypted,
      lastUsedCounter: null,
    });

    (TotpCredential.findOne as any).mockResolvedValue(firstCredential);

    const firstResult = await verifyEnabledTotp('user-1', code);
    const usedCounter = firstCredential.update.mock.calls[0][0].lastUsedCounter;
    const replayedCredential = buildTotpCredential({
      ...encrypted,
      lastUsedCounter: usedCounter,
    });

    (TotpCredential.findOne as any).mockResolvedValue(replayedCredential);

    const replayResult = await verifyEnabledTotp('user-1', code);

    expect(firstResult.verified).toBe(true);
    expect(replayResult.verified).toBe(false);
    expect(replayedCredential.update).not.toHaveBeenCalled();
  });

  it('reports enabled status from the active credential', async () => {
    const credential = buildTotpCredential({
      enabled: true,
      verifiedAt: new Date('2026-01-01T00:00:00.000Z'),
      lastUsedAt: new Date('2026-01-02T00:00:00.000Z'),
    });

    (TotpCredential.findOne as any).mockResolvedValue(credential);

    await expect(getTotpStatus('user-1')).resolves.toEqual({
      enabled: true,
      verifiedAt: credential.verifiedAt,
      lastUsedAt: credential.lastUsedAt,
    });
    expect(TotpCredential.findOne).toHaveBeenCalledWith({
      where: { userId: 'user-1', enabled: true },
    });
  });

  it('reports disabled status when no active credential exists', async () => {
    (TotpCredential.findOne as any).mockResolvedValue(null);

    await expect(getTotpStatus('user-1')).resolves.toEqual({
      enabled: false,
      verifiedAt: null,
      lastUsedAt: null,
    });
  });

  it('rejects enrollment verification when no pending credential exists', async () => {
    (TotpCredential.findOne as any).mockResolvedValue(null);

    await expect(verifyTotpEnrollment('user-1', '123456')).resolves.toEqual({
      verified: false,
      reason: 'missing_pending_credential',
    });
    expect(TotpCredential.update).not.toHaveBeenCalled();
  });

  it('rejects enrollment verification when the submitted code is invalid', async () => {
    const encrypted = encryptTotpSecret('JBSWY3DPEHPK3PXP');
    const credential = buildTotpCredential({ ...encrypted, enabled: false, lastUsedCounter: null });

    (TotpCredential.findOne as any).mockResolvedValue(credential);

    await expect(verifyTotpEnrollment('user-1', '000000')).resolves.toEqual({
      verified: false,
      reason: 'invalid_code',
    });
    expect(credential.update).not.toHaveBeenCalled();
    expect(TotpCredential.update).not.toHaveBeenCalled();
  });

  it('rejects enabled verification when no enabled credential exists', async () => {
    (TotpCredential.findOne as any).mockResolvedValue(null);

    await expect(verifyEnabledTotp('user-1', '123456')).resolves.toEqual({
      verified: false,
      reason: 'missing_enabled_credential',
    });
  });

  it('rejects enabled verification when the submitted code is invalid', async () => {
    const encrypted = encryptTotpSecret('JBSWY3DPEHPK3PXP');
    const credential = buildTotpCredential({ ...encrypted, lastUsedCounter: null });

    (TotpCredential.findOne as any).mockResolvedValue(credential);

    await expect(verifyEnabledTotp('user-1', '000000')).resolves.toEqual({
      verified: false,
      reason: 'invalid_code',
    });
    expect(credential.update).not.toHaveBeenCalled();
  });

  it('rejects disabling when no enabled credential exists', async () => {
    (TotpCredential.findOne as any).mockResolvedValue(null);

    await expect(disableTotp('user-1', '123456')).resolves.toEqual({
      disabled: false,
      reason: 'missing_enabled_credential',
    });
  });

  it('rejects disabling when the submitted code is invalid', async () => {
    const encrypted = encryptTotpSecret('JBSWY3DPEHPK3PXP');
    const credential = buildTotpCredential({ ...encrypted, lastUsedCounter: null });

    (TotpCredential.findOne as any).mockResolvedValue(credential);

    await expect(disableTotp('user-1', '000000')).resolves.toEqual({
      disabled: false,
      reason: 'invalid_code',
    });
    expect(credential.destroy).not.toHaveBeenCalled();
  });

  it('disables the credential when a valid code is provided', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptTotpSecret(secret);
    const credential = buildTotpCredential({ ...encrypted, lastUsedCounter: null });
    const code = generateTotpCode({ secret });

    (TotpCredential.findOne as any).mockResolvedValue(credential);

    await expect(disableTotp('user-1', code)).resolves.toEqual({ disabled: true });
    expect(credential.destroy).toHaveBeenCalled();
  });

  it('uses randomBytes output directly when it returns a Buffer', () => {
    (randomBytes as any).mockReturnValueOnce(Buffer.alloc(12, 7));

    const encrypted = encryptTotpSecret('JBSWY3DPEHPK3PXP');

    expect(Buffer.from(encrypted.secretIv, 'base64')).toHaveLength(12);
  });

  it('truncates an oversized non-Buffer randomBytes fallback to the requested length', () => {
    (randomBytes as any).mockReturnValueOnce({ toString: () => 'x'.repeat(32) });

    const encrypted = encryptTotpSecret('JBSWY3DPEHPK3PXP');

    expect(Buffer.from(encrypted.secretIv, 'base64')).toHaveLength(12);
  });

  it('derives a development encryption key when no explicit secret is configured', () => {
    const previous = {
      key: process.env.TOTP_SECRET_ENCRYPTION_KEY,
      service: process.env.API_SERVICE_TOKEN,
      env: process.env.NODE_ENV,
    };
    delete process.env.TOTP_SECRET_ENCRYPTION_KEY;
    delete process.env.API_SERVICE_TOKEN;
    process.env.NODE_ENV = 'test';

    try {
      const secret = 'JBSWY3DPEHPK3PXP';
      const encrypted = encryptTotpSecret(secret);
      const credential = buildTotpCredential({ ...encrypted });

      expect(decryptTotpSecret(credential)).toBe(secret);
    } finally {
      process.env.TOTP_SECRET_ENCRYPTION_KEY = previous.key;
      if (previous.service === undefined) delete process.env.API_SERVICE_TOKEN;
      else process.env.API_SERVICE_TOKEN = previous.service;
      process.env.NODE_ENV = previous.env;
    }
  });

  it('falls back to API_SERVICE_TOKEN as the encryption secret', () => {
    const previous = process.env.TOTP_SECRET_ENCRYPTION_KEY;
    const previousService = process.env.API_SERVICE_TOKEN;
    delete process.env.TOTP_SECRET_ENCRYPTION_KEY;
    process.env.API_SERVICE_TOKEN = 'service-token';

    try {
      const secret = 'JBSWY3DPEHPK3PXP';
      const encrypted = encryptTotpSecret(secret);
      const credential = buildTotpCredential({ ...encrypted });

      expect(decryptTotpSecret(credential)).toBe(secret);
    } finally {
      process.env.TOTP_SECRET_ENCRYPTION_KEY = previous;
      if (previousService === undefined) delete process.env.API_SERVICE_TOKEN;
      else process.env.API_SERVICE_TOKEN = previousService;
    }
  });

  it('requires an encryption secret in production', () => {
    const previous = {
      key: process.env.TOTP_SECRET_ENCRYPTION_KEY,
      service: process.env.API_SERVICE_TOKEN,
      env: process.env.NODE_ENV,
    };
    delete process.env.TOTP_SECRET_ENCRYPTION_KEY;
    delete process.env.API_SERVICE_TOKEN;
    process.env.NODE_ENV = 'production';

    try {
      expect(() => encryptTotpSecret('JBSWY3DPEHPK3PXP')).toThrow(
        'TOTP_SECRET_ENCRYPTION_KEY or API_SERVICE_TOKEN must be set in production.',
      );
    } finally {
      process.env.TOTP_SECRET_ENCRYPTION_KEY = previous.key;
      if (previous.service === undefined) delete process.env.API_SERVICE_TOKEN;
      else process.env.API_SERVICE_TOKEN = previous.service;
      process.env.NODE_ENV = previous.env;
    }
  });
});
