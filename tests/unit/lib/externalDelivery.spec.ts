import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/middleware/authenticateServiceToken.js', () => ({
  validateInternalServiceToken: vi.fn(),
}));

import { validateInternalServiceToken } from '../../../src/middleware/authenticateServiceToken.js';
import {
  canReturnExternalDelivery,
  canReturnSensitiveDevelopmentDetails,
} from '../../../src/lib/externalDelivery.js';

function req(headers: Record<string, string | undefined>) {
  return {
    get: (name: string) => headers[name.toLowerCase()],
  } as any;
}

describe('external delivery gates', () => {
  const originalNodeEnv = process.env.NODE_ENV;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.NODE_ENV = 'test';
  });

  afterEach(() => {
    if (originalNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it('allows explicit external delivery outside production', async () => {
    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
        }),
      ),
    ).resolves.toBe(true);
  });

  it('requires a valid internal service token in production', async () => {
    process.env.NODE_ENV = 'production';
    (validateInternalServiceToken as any).mockResolvedValue({
      sub: 'service',
      iss: 'seamless-portal-api',
      aud: 'seamless-auth',
    });

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': 'Bearer service-token',
        }),
      ),
    ).resolves.toBe(true);

    expect(validateInternalServiceToken).toHaveBeenCalledWith('service-token');
  });

  it('blocks external delivery in production without a trusted service token', async () => {
    process.env.NODE_ENV = 'production';
    (validateInternalServiceToken as any).mockResolvedValue(null);

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': 'Bearer invalid',
        }),
      ),
    ).resolves.toBe(false);
  });

  it('does not attempt delivery when the external mode header is absent', async () => {
    await expect(canReturnExternalDelivery(req({}))).resolves.toBe(false);
    expect(validateInternalServiceToken).not.toHaveBeenCalled();
  });

  it('blocks external delivery in production when the service token header is missing', async () => {
    process.env.NODE_ENV = 'production';

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
        }),
      ),
    ).resolves.toBe(false);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
  });

  it('treats an empty Bearer service token as missing in production', async () => {
    process.env.NODE_ENV = 'production';

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': 'Bearer ',
        }),
      ),
    ).resolves.toBe(false);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
  });

  it('accepts a raw (non-Bearer) service token value in production', async () => {
    process.env.NODE_ENV = 'production';
    (validateInternalServiceToken as any).mockResolvedValue({
      sub: 'service',
      iss: 'seamless-portal-api',
      aud: 'seamless-auth',
    });

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': 'raw-token',
        }),
      ),
    ).resolves.toBe(true);

    expect(validateInternalServiceToken).toHaveBeenCalledWith('raw-token');
  });

  it('treats a whitespace-only service token as missing in production', async () => {
    process.env.NODE_ENV = 'production';

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': '   ',
        }),
      ),
    ).resolves.toBe(false);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
  });

  it('requires explicit sensitive-details opt-in outside production', () => {
    expect(
      canReturnSensitiveDevelopmentDetails(
        req({
          'x-seamless-auth-include-sensitive': 'true',
        }),
      ),
    ).toBe(true);
  });

  it('never returns sensitive details in production', () => {
    process.env.NODE_ENV = 'production';

    expect(
      canReturnSensitiveDevelopmentDetails(
        req({
          'x-seamless-auth-include-sensitive': 'true',
        }),
      ),
    ).toBe(false);
  });
});
