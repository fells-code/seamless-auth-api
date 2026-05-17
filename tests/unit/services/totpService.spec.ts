import { beforeEach, describe, expect, it, vi } from 'vitest';

import { TotpCredential } from '../../../src/models/totpCredentials.js';
import {
  encryptTotpSecret,
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
});
