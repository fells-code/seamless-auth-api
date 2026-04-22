import { vi } from 'vitest';

const sendOtpEmailMock = vi.fn();
const sendOtpSmsMock = vi.fn();
const sendMagicLinkEmailMock = vi.fn();
const sendBootstrapInviteEmailMock = vi.fn();
const createDirectAuthMessagingServiceMock = vi.fn(() => ({
  sendOtpEmail: sendOtpEmailMock,
  sendOtpSms: sendOtpSmsMock,
  sendMagicLinkEmail: sendMagicLinkEmailMock,
  sendBootstrapInviteEmail: sendBootstrapInviteEmailMock,
}));

vi.unmock('../../../src/services/messagingService');
vi.mock('../../../src/config/directMessaging', () => ({
  createDirectAuthMessagingService: createDirectAuthMessagingServiceMock,
}));
vi.mock('../../../src/config/getSystemConfig', () => ({
  getSystemConfig: vi.fn().mockResolvedValue({
    app_name: 'Seamless Auth Test',
  }),
}));
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
    process.env.MESSAGING_ENABLE_IN_DEV = '';
  });

  it('does nothing in development (email)', async () => {
    process.env.NODE_ENV = 'development';

    const { sendOTPEmail } = await import('../../../src/services/messagingService');

    await expect(sendOTPEmail('test@example.com', '123456')).resolves.toBeUndefined();
    expect(createDirectAuthMessagingServiceMock).not.toHaveBeenCalled();
  });

  it('does nothing in development (sms)', async () => {
    process.env.NODE_ENV = 'development';

    const { sendOTPSMS } = await import('../../../src/services/messagingService');

    await expect(sendOTPSMS('+123', 123456)).resolves.toBeUndefined();
    expect(createDirectAuthMessagingServiceMock).not.toHaveBeenCalled();
  });

  it('does nothing in development (magic link)', async () => {
    process.env.NODE_ENV = 'development';

    const { sendMagicLinkEmail } = await import('../../../src/services/messagingService');

    await expect(
      sendMagicLinkEmail('test@example.com', 'token', 'http://safe'),
    ).resolves.toBeUndefined();
    expect(createDirectAuthMessagingServiceMock).not.toHaveBeenCalled();
  });

  it('can execute direct delivery in development when enabled', async () => {
    process.env.NODE_ENV = 'development';
    process.env.MESSAGING_ENABLE_IN_DEV = 'true';

    const { sendOTPEmail } = await import('../../../src/services/messagingService');

    await expect(sendOTPEmail('test@example.com', '123456')).resolves.toBeUndefined();

    expect(createDirectAuthMessagingServiceMock).toHaveBeenCalledWith('Seamless Auth Test');
    expect(sendOtpEmailMock).toHaveBeenCalledWith({
      to: 'test@example.com',
      token: '123456',
    });
  });

  it('does not throw in production', async () => {
    process.env.NODE_ENV = 'production';

    const { sendOTPEmail } = await import('../../../src/services/messagingService');

    await expect(sendOTPEmail('test@example.com', '123')).resolves.toBeUndefined();
    expect(createDirectAuthMessagingServiceMock).toHaveBeenCalledWith('Seamless Auth Test');
  });
});
