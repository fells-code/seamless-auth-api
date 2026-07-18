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

  it('propagates production email delivery failures', async () => {
    process.env.NODE_ENV = 'production';
    sendOtpEmailMock.mockRejectedValueOnce(new Error('provider down'));

    const { sendOTPEmail } = await import('../../../src/services/messagingService');

    await expect(sendOTPEmail('test@example.com', '123')).rejects.toThrow('provider down');
  });

  it('propagates production SMS delivery failures', async () => {
    process.env.NODE_ENV = 'production';
    sendOtpSmsMock.mockRejectedValueOnce(new Error('sms down'));

    const { sendOTPSMS } = await import('../../../src/services/messagingService');

    await expect(sendOTPSMS('+14155552671', 123456)).rejects.toThrow('sms down');
  });

  it('propagates production magic-link delivery failures', async () => {
    process.env.NODE_ENV = 'production';
    sendMagicLinkEmailMock.mockRejectedValueOnce(new Error('email down'));

    const { sendMagicLinkEmail } = await import('../../../src/services/messagingService');

    await expect(
      sendMagicLinkEmail('test@example.com', 'token', 'https://app.example.com/verify'),
    ).rejects.toThrow('email down');
  });

  it('rejects SMS delivery to an unparseable phone number', async () => {
    process.env.NODE_ENV = 'production';

    const { sendOTPSMS } = await import('../../../src/services/messagingService');

    await expect(sendOTPSMS('not-a-phone', 123456)).rejects.toThrow(
      'Invalid phone number for direct SMS delivery',
    );
    expect(sendOtpSmsMock).not.toHaveBeenCalled();
  });

  it('normalizes valid phone numbers before direct SMS delivery', async () => {
    process.env.NODE_ENV = 'production';

    const { sendOTPSMS } = await import('../../../src/services/messagingService');

    await expect(sendOTPSMS('+14155552671', 123456)).resolves.toBeUndefined();
    expect(sendOtpSmsMock).toHaveBeenCalledWith({ to: '+14155552671', token: 123456 });
  });

  it('does nothing in development (bootstrap invite)', async () => {
    process.env.NODE_ENV = 'development';

    const { sendBootstrapEmail } = await import('../../../src/services/messagingService');

    await expect(
      sendBootstrapEmail('admin@example.com', 'https://app.example.com/invite'),
    ).resolves.toBeUndefined();
    expect(createDirectAuthMessagingServiceMock).not.toHaveBeenCalled();
  });

  it('sends bootstrap invite emails in production', async () => {
    process.env.NODE_ENV = 'production';

    const { sendBootstrapEmail } = await import('../../../src/services/messagingService');

    await expect(
      sendBootstrapEmail('admin@example.com', 'https://app.example.com/invite'),
    ).resolves.toBeUndefined();
    expect(sendBootstrapInviteEmailMock).toHaveBeenCalledWith({
      to: 'admin@example.com',
      inviteUrl: 'https://app.example.com/invite',
    });
  });

  it('propagates production bootstrap delivery failures', async () => {
    process.env.NODE_ENV = 'production';
    sendBootstrapInviteEmailMock.mockRejectedValueOnce(new Error('bootstrap down'));

    const { sendBootstrapEmail } = await import('../../../src/services/messagingService');

    await expect(
      sendBootstrapEmail('admin@example.com', 'https://app.example.com/invite'),
    ).rejects.toThrow('bootstrap down');
  });
});
