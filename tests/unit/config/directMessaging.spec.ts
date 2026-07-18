import { beforeEach, describe, expect, it, vi } from 'vitest';

const createAuthMessagingServiceMock = vi.fn();
const createAwsEmailTransportMock = vi.fn();
const createAwsSmsTransportMock = vi.fn();
const createTwilioSmsTransportMock = vi.fn();

vi.unmock('../../../src/config/directMessaging.js');

vi.mock('@seamless-auth/messaging', () => {
  class MessagingConfigurationError extends Error {}

  return {
    MessagingConfigurationError,
    createAuthMessagingService: createAuthMessagingServiceMock,
  };
});

vi.mock('@seamless-auth/messaging-aws', () => ({
  createAwsEmailTransport: createAwsEmailTransportMock,
  createAwsSmsTransport: createAwsSmsTransportMock,
}));

vi.mock('@seamless-auth/messaging-twilio', () => ({
  createTwilioSmsTransport: createTwilioSmsTransportMock,
}));

describe('directMessaging config', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    delete process.env.MESSAGING_AWS_REGION;
    delete process.env.AWS_REGION;
    delete process.env.REGION;
    delete process.env.MESSAGING_EMAIL_FROM;
    delete process.env.SES_EMAIL;
    delete process.env.MESSAGING_SMS_PROVIDER;
    delete process.env.SMS_PROVIDER;
    delete process.env.MESSAGING_TWILIO_ACCOUNT_SID;
    delete process.env.TWILIO_ACCOUNT_SID;
    delete process.env.MESSAGING_TWILIO_AUTH_TOKEN;
    delete process.env.TWILIO_AUTH_TOKEN;
    delete process.env.MESSAGING_SMS_FROM;
    delete process.env.TWILIO_PHONE_NUMBER;

    createAwsEmailTransportMock.mockReturnValue({ name: 'aws-email' });
    createAwsSmsTransportMock.mockReturnValue({ name: 'aws-sms' });
    createTwilioSmsTransportMock.mockReturnValue({ name: 'twilio-sms' });
    createAuthMessagingServiceMock.mockReturnValue({ name: 'messaging-service' });
  });

  it('builds direct messaging with AWS defaults', async () => {
    process.env.AWS_REGION = 'us-east-1';
    process.env.SES_EMAIL = 'noreply@example.com';

    const { createDirectAuthMessagingService } =
      await import('../../../src/config/directMessaging.js');

    const result = createDirectAuthMessagingService('Test App');

    expect(createAwsEmailTransportMock).toHaveBeenCalledWith({
      region: 'us-east-1',
      fromEmail: 'noreply@example.com',
    });
    expect(createAwsSmsTransportMock).toHaveBeenCalledWith({
      region: 'us-east-1',
      senderId: undefined,
    });
    expect(createAuthMessagingServiceMock).toHaveBeenCalledWith({
      appName: 'Test App',
      email: { name: 'aws-email' },
      sms: { name: 'aws-sms' },
    });
    expect(result).toEqual({ name: 'messaging-service' });
  });

  it('builds Twilio SMS transport when configured', async () => {
    process.env.MESSAGING_AWS_REGION = 'us-west-2';
    process.env.MESSAGING_EMAIL_FROM = 'alerts@example.com';
    process.env.MESSAGING_SMS_PROVIDER = 'twilio';
    process.env.MESSAGING_TWILIO_ACCOUNT_SID = 'sid';
    process.env.MESSAGING_TWILIO_AUTH_TOKEN = 'token';
    process.env.MESSAGING_SMS_FROM = '+15555550123';

    const { createDirectAuthMessagingService } =
      await import('../../../src/config/directMessaging.js');

    createDirectAuthMessagingService('Test App');

    expect(createAwsEmailTransportMock).toHaveBeenCalledWith({
      region: 'us-west-2',
      fromEmail: 'alerts@example.com',
    });
    expect(createTwilioSmsTransportMock).toHaveBeenCalledWith({
      accountSid: 'sid',
      authToken: 'token',
      fromNumber: '+15555550123',
    });
    expect(createAwsSmsTransportMock).not.toHaveBeenCalled();
  });

  it('throws for an unsupported SMS provider', async () => {
    process.env.MESSAGING_AWS_REGION = 'us-east-1';
    process.env.MESSAGING_EMAIL_FROM = 'noreply@example.com';
    process.env.MESSAGING_SMS_PROVIDER = 'postal-pigeon';

    const { createDirectAuthMessagingService } =
      await import('../../../src/config/directMessaging.js');

    expect(() => createDirectAuthMessagingService('Test App')).toThrow(
      'Unsupported MESSAGING_SMS_PROVIDER "postal-pigeon"',
    );
  });

  it('throws when no AWS region is configured for email delivery', async () => {
    process.env.SES_EMAIL = 'noreply@example.com';

    const { createDirectAuthMessagingService } =
      await import('../../../src/config/directMessaging.js');

    expect(() => createDirectAuthMessagingService('Test App')).toThrow(
      'MESSAGING_AWS_REGION or AWS_REGION is required for direct email delivery.',
    );
  });

  it('throws when no from email is configured for email delivery', async () => {
    process.env.AWS_REGION = 'us-east-1';

    const { createDirectAuthMessagingService } =
      await import('../../../src/config/directMessaging.js');

    expect(() => createDirectAuthMessagingService('Test App')).toThrow(
      'MESSAGING_EMAIL_FROM is required for direct email delivery.',
    );
  });

  it('throws when Twilio credentials are incomplete', async () => {
    process.env.AWS_REGION = 'us-east-1';
    process.env.SES_EMAIL = 'noreply@example.com';
    process.env.MESSAGING_SMS_PROVIDER = 'twilio';

    const { createDirectAuthMessagingService } =
      await import('../../../src/config/directMessaging.js');

    expect(() => createDirectAuthMessagingService('Test App')).toThrow(
      'MESSAGING_TWILIO_ACCOUNT_SID, MESSAGING_TWILIO_AUTH_TOKEN, and MESSAGING_SMS_FROM are required when MESSAGING_SMS_PROVIDER=twilio.',
    );
    expect(createTwilioSmsTransportMock).not.toHaveBeenCalled();
  });
});
