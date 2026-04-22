import { vi } from 'vitest';

vi.unmock('../../../src/services/messagingService');
vi.mock('../../../src/utils/logger', () => ({
  default: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    error: vi.fn(),
  }),
}));

import { describe, it, expect, beforeEach } from 'vitest';

describe('messagingService', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('does nothing in development (email)', async () => {
    process.env.NODE_ENV = 'development';

    const { sendOTPEmail } = await import('../../../src/services/messagingService');

    await expect(sendOTPEmail('test@example.com', '123456')).resolves.toBeUndefined();
  });

  it('does nothing in development (sms)', async () => {
    process.env.NODE_ENV = 'development';

    const { sendOTPSMS } = await import('../../../src/services/messagingService');

    await expect(sendOTPSMS('+123', 123456)).resolves.toBeUndefined();
  });

  it('does nothing in development (magic link)', async () => {
    process.env.NODE_ENV = 'development';

    const { sendMagicLinkEmail } = await import('../../../src/services/messagingService');

    await expect(
      sendMagicLinkEmail('test@example.com', 'token', 'http://safe'),
    ).resolves.toBeUndefined();
  });

  it('does not throw in production', async () => {
    process.env.NODE_ENV = 'production';

    const { sendOTPEmail } = await import('../../../src/services/messagingService');

    await expect(sendOTPEmail('test@example.com', '123')).resolves.toBeUndefined();
  });
});
