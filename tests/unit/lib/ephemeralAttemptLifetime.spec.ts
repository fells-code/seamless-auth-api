import { generateKeyPairSync } from 'crypto';
import { decodeJwt } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.unmock('../../../src/lib/token');

vi.hoisted(() => {
  process.env.ISSUER = 'https://auth.example.com';
});

vi.mock('../../../src/utils/signingKeyStore.js', () => ({
  getSigningKey: vi.fn(),
}));

import { EPHEMERAL_TOKEN_TTL_SECONDS } from '../../../src/lib/ephemeralTokenTtl.js';
import { reissueEphemeralToken, signEphemeralToken } from '../../../src/lib/token.js';
import { getSigningKey } from '../../../src/utils/signingKeyStore.js';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const START = new Date('2026-11-17T12:00:00Z');

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(START);
  (getSigningKey as any).mockResolvedValue({ kid: 'k1', privateKeyPem });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('ephemeral attempt lifetime', () => {
  it('ends every re-minted token where the attempt began, however often it is re-minted', async () => {
    const first = decodeJwt(await signEphemeralToken('user-1'));
    const attemptEnds = START.getTime() / 1000 + EPHEMERAL_TOKEN_TTL_SECONDS;

    expect(first.exp).toBe(attemptEnds);

    let current = first;

    for (let minute = 1; minute <= 4; minute += 1) {
      vi.setSystemTime(new Date(START.getTime() + minute * 60_000));

      current = decodeJwt(
        await reissueEphemeralToken('user-1', {
          attemptId: current.jti,
          attemptExpiresAt: current.exp,
        }),
      );

      expect(current.jti).toBe(first.jti);
      expect(current.exp).toBe(attemptEnds);
    }
  });
});
