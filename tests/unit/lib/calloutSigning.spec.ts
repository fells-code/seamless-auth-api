import { createHmac, timingSafeEqual } from 'node:crypto';

import { CalloutSecretSchema } from '@seamless-auth/types';
import { describe, expect, it, vi } from 'vitest';

import {
  calloutSignature,
  decryptCalloutSecret,
  encryptCalloutSecret,
  generateCalloutSecret,
  signedCalloutHeaders,
} from '../../../src/lib/calloutSigning.js';

// The shared setup makes randomBytes constant, and these tests need distinct secrets.
vi.unmock('crypto');

/** A receiver's check, written from the Standard Webhooks spec rather than from our signer. */
function verifies(secret: string, id: string, timestamp: string, body: string, header: string) {
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
  const expected = createHmac('sha256', key).update(`${id}.${timestamp}.${body}`).digest();

  return header.split(' ').some((entry) => {
    const [version, signature] = entry.split(',');
    const given = Buffer.from(signature ?? '', 'base64');
    return version === 'v1' && given.length === expected.length && timingSafeEqual(given, expected);
  });
}

describe('callout secrets', () => {
  it('generates a whsec_ secret of 32 random bytes', () => {
    const secret = generateCalloutSecret();

    expect(CalloutSecretSchema.safeParse(secret).success).toBe(true);
    expect(generateCalloutSecret()).not.toBe(secret);
  });

  it('round-trips through encryption at rest', () => {
    const secret = generateCalloutSecret();
    const sealed = encryptCalloutSecret(secret);

    expect(sealed.ciphertext).not.toContain(secret.slice(6));
    expect(decryptCalloutSecret(sealed)).toBe(secret);
  });

  it('refuses a ciphertext that was tampered with', () => {
    const sealed = encryptCalloutSecret(generateCalloutSecret());
    const flipped = Buffer.from(sealed.ciphertext, 'base64');
    flipped[0] ^= 1;

    expect(() =>
      decryptCalloutSecret({ ...sealed, ciphertext: flipped.toString('base64') }),
    ).toThrow();
  });

  it('cannot be read under another key', () => {
    const sealed = encryptCalloutSecret(generateCalloutSecret());
    vi.stubEnv('CALLOUT_SECRET_ENCRYPTION_KEY', 'a different key');

    expect(() => decryptCalloutSecret(sealed)).toThrow();
  });
});

describe('signedCalloutHeaders', () => {
  const body = '{"type":"user.created"}';
  const at = new Date('2026-11-07T12:00:00.000Z');

  it('signs id, timestamp and body the way a Standard Webhooks receiver checks them', () => {
    const secret = generateCalloutSecret();
    const headers = signedCalloutHeaders('msg_1', body, [secret], at);

    expect(headers['content-type']).toBe('application/json');
    expect(headers['webhook-id']).toBe('msg_1');
    expect(headers['webhook-timestamp']).toBe(String(at.getTime() / 1000));
    expect(
      verifies(secret, 'msg_1', headers['webhook-timestamp'], body, headers['webhook-signature']),
    ).toBe(true);
  });

  it('does not verify a changed body, id or timestamp', () => {
    const secret = generateCalloutSecret();
    const headers = signedCalloutHeaders('msg_1', body, [secret], at);
    const ts = headers['webhook-timestamp'];
    const signature = headers['webhook-signature'];

    expect(verifies(secret, 'msg_1', ts, `${body} `, signature)).toBe(false);
    expect(verifies(secret, 'msg_2', ts, body, signature)).toBe(false);
    expect(verifies(secret, 'msg_1', String(Number(ts) + 1), body, signature)).toBe(false);
    expect(verifies(generateCalloutSecret(), 'msg_1', ts, body, signature)).toBe(false);
  });

  it('signs with both secrets while one rotates, so either verifies', () => {
    const current = generateCalloutSecret();
    const previous = generateCalloutSecret();
    const headers = signedCalloutHeaders('msg_1', body, [current, previous], at);
    const ts = headers['webhook-timestamp'];

    expect(headers['webhook-signature'].split(' ')).toHaveLength(2);
    expect(verifies(current, 'msg_1', ts, body, headers['webhook-signature'])).toBe(true);
    expect(verifies(previous, 'msg_1', ts, body, headers['webhook-signature'])).toBe(true);
  });

  it('defaults the timestamp to now', () => {
    vi.useFakeTimers({ now: at });
    try {
      const headers = signedCalloutHeaders('msg_1', body, [generateCalloutSecret()]);
      expect(headers['webhook-timestamp']).toBe(String(at.getTime() / 1000));
    } finally {
      vi.useRealTimers();
    }
  });

  it('formats one signature as v1 and base64', () => {
    expect(calloutSignature('a', 1, 'b', generateCalloutSecret())).toMatch(/^v1,[A-Za-z0-9+/]+=*$/);
  });
});
