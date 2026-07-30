import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/middleware/authenticateServiceToken.js', () => ({
  validateInternalServiceToken: vi.fn(),
}));

import { validateInternalServiceToken } from '../../../src/middleware/authenticateServiceToken.js';
import { canReturnExternalDelivery } from '../../../src/lib/externalDelivery.js';

function req(headers: Record<string, string | undefined>) {
  return {
    get: (name: string) => headers[name.toLowerCase()],
  } as any;
}

describe('external delivery gates', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalOptIn = process.env.ALLOW_UNCREDENTIALED_DELIVERY_SECRETS;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.NODE_ENV = 'test';
    delete process.env.ALLOW_UNCREDENTIALED_DELIVERY_SECRETS;
  });

  afterEach(() => {
    if (originalNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = originalNodeEnv;
    }

    if (originalOptIn === undefined) {
      delete process.env.ALLOW_UNCREDENTIALED_DELIVERY_SECRETS;
    } else {
      process.env.ALLOW_UNCREDENTIALED_DELIVERY_SECRETS = originalOptIn;
    }
  });

  it('blocks external delivery outside production without a trusted service token', async () => {
    (validateInternalServiceToken as any).mockResolvedValue(null);

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
        }),
      ),
    ).resolves.toBe(false);
  });

  it('allows external delivery with a trusted service token outside production', async () => {
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
  });

  it('rejects a token from an untrusted issuer or audience', async () => {
    (validateInternalServiceToken as any).mockResolvedValue({
      sub: 'service',
      iss: 'someone-else',
      aud: 'seamless-auth',
    });

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
          'x-seamless-service-token': 'Bearer service-token',
        }),
      ),
    ).resolves.toBe(false);
  });

  it('allows uncredentialed external delivery only behind the explicit local opt-in', async () => {
    process.env.ALLOW_UNCREDENTIALED_DELIVERY_SECRETS = 'true';

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
        }),
      ),
    ).resolves.toBe(true);

    expect(validateInternalServiceToken).not.toHaveBeenCalled();
  });

  it('ignores the local opt-in in production', async () => {
    process.env.NODE_ENV = 'production';
    process.env.ALLOW_UNCREDENTIALED_DELIVERY_SECRETS = 'true';

    await expect(
      canReturnExternalDelivery(
        req({
          'x-seamless-auth-delivery-mode': 'external',
        }),
      ),
    ).resolves.toBe(false);
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
});
