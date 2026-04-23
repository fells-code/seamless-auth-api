/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import {
  type AuthMessagingService,
  createAuthMessagingService,
  MessagingConfigurationError,
} from '@seamless-auth/messaging';
import { createAwsEmailTransport, createAwsSmsTransport } from '@seamless-auth/messaging-aws';
import { createTwilioSmsTransport } from '@seamless-auth/messaging-twilio';

export type DirectSmsProvider = 'aws' | 'twilio';

function getAwsRegion(): string | undefined {
  return process.env.MESSAGING_AWS_REGION ?? process.env.AWS_REGION ?? process.env.REGION;
}

function getEmailFrom(): string | undefined {
  return process.env.MESSAGING_EMAIL_FROM ?? process.env.SES_EMAIL;
}

function getSmsProvider(): DirectSmsProvider {
  const rawProvider = (
    process.env.MESSAGING_SMS_PROVIDER ??
    process.env.SMS_PROVIDER ??
    'aws'
  ).toLowerCase();

  if (rawProvider !== 'aws' && rawProvider !== 'twilio') {
    throw new MessagingConfigurationError(
      `Unsupported MESSAGING_SMS_PROVIDER "${rawProvider}". Expected "aws" or "twilio".`,
    );
  }

  return rawProvider;
}

function getTwilioAccountSid(): string | undefined {
  return process.env.MESSAGING_TWILIO_ACCOUNT_SID ?? process.env.TWILIO_ACCOUNT_SID;
}

function getTwilioAuthToken(): string | undefined {
  return process.env.MESSAGING_TWILIO_AUTH_TOKEN ?? process.env.TWILIO_AUTH_TOKEN;
}

function getSmsFrom(): string | undefined {
  return process.env.MESSAGING_SMS_FROM ?? process.env.TWILIO_PHONE_NUMBER;
}

function buildEmailTransport() {
  const region = getAwsRegion();
  const fromEmail = getEmailFrom();

  if (!region) {
    throw new MessagingConfigurationError(
      'MESSAGING_AWS_REGION or AWS_REGION is required for direct email delivery.',
    );
  }

  if (!fromEmail) {
    throw new MessagingConfigurationError(
      'MESSAGING_EMAIL_FROM is required for direct email delivery.',
    );
  }

  return createAwsEmailTransport({
    region,
    fromEmail,
  });
}

function buildSmsTransport() {
  const provider = getSmsProvider();

  if (provider === 'aws') {
    const region = getAwsRegion();

    if (!region) {
      throw new MessagingConfigurationError(
        'MESSAGING_AWS_REGION or AWS_REGION is required when MESSAGING_SMS_PROVIDER=aws.',
      );
    }

    return createAwsSmsTransport({
      region,
      senderId: getSmsFrom(),
    });
  }

  const accountSid = getTwilioAccountSid();
  const authToken = getTwilioAuthToken();
  const fromNumber = getSmsFrom();

  if (!accountSid || !authToken || !fromNumber) {
    throw new MessagingConfigurationError(
      'MESSAGING_TWILIO_ACCOUNT_SID, MESSAGING_TWILIO_AUTH_TOKEN, and MESSAGING_SMS_FROM are required when MESSAGING_SMS_PROVIDER=twilio.',
    );
  }

  return createTwilioSmsTransport({
    accountSid,
    authToken,
    fromNumber,
  });
}

export function createDirectAuthMessagingService(appName: string): AuthMessagingService {
  return createAuthMessagingService({
    appName,
    email: buildEmailTransport(),
    sms: buildSmsTransport(),
  });
}
