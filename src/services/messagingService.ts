/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { SendEmailCommand, type SendEmailCommandInput, SESClient } from '@aws-sdk/client-ses';
import { PublishCommand, type PublishCommandInput, SNSClient } from '@aws-sdk/client-sns';
import twilio from 'twilio';

import { getSystemConfig } from '../config/getSystemConfig.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('messaging');

const isDevelopment = process.env.NODE_ENV === 'development';
const smsProvider = (process.env.SMS_PROVIDER ?? 'aws').toLowerCase();

function getAwsRegion() {
  return process.env.AWS_REGION ?? process.env.REGION;
}

function createSesClient() {
  const region = getAwsRegion();

  if (!region) {
    throw new Error('AWS_REGION or REGION is required to send email.');
  }

  return new SESClient({ region });
}

function createSnsClient() {
  const region = getAwsRegion();

  if (!region) {
    throw new Error('AWS_REGION or REGION is required to send SMS through AWS SNS.');
  }

  return new SNSClient({ region });
}

function createTwilioClient() {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;

  if (!accountSid || !authToken) {
    throw new Error('TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN are required.');
  }

  return twilio(accountSid, authToken);
}

function getSesSourceEmail() {
  const source = process.env.SES_EMAIL;

  if (!source) {
    throw new Error('SES_EMAIL is required to send email.');
  }

  return source;
}

async function sendEmail(params: { to: string; subject: string; html: string }) {
  if (isDevelopment) {
    return;
  }

  const ses = createSesClient();
  const input: SendEmailCommandInput = {
    Source: getSesSourceEmail(),
    Destination: {
      ToAddresses: [params.to],
    },
    ReplyToAddresses: [],
    Message: {
      Body: {
        Html: {
          Charset: 'UTF-8',
          Data: params.html,
        },
      },
      Subject: {
        Charset: 'UTF-8',
        Data: params.subject,
      },
    },
  };

  await ses.send(new SendEmailCommand(input));
}

async function sendSmsWithAws(to: string, body: string) {
  const sns = createSnsClient();
  const input: PublishCommandInput = {
    PhoneNumber: to,
    Message: body,
  };

  await sns.send(new PublishCommand(input));
}

async function sendSmsWithTwilio(to: string, body: string) {
  const from = process.env.TWILIO_PHONE_NUMBER;

  if (!from) {
    throw new Error('TWILIO_PHONE_NUMBER is required.');
  }

  const client = createTwilioClient();
  await client.messages.create({
    to,
    from,
    body,
  });
}

export const sendOTPEmail = async (to: string, token: string) => {
  logger.debug(`Sending verification email to: ${to} with ${token}`);

  if (isDevelopment) {
    return;
  }

  try {
    const { app_name } = await getSystemConfig();

    await sendEmail({
      to,
      subject: `${app_name} - Verify your email`,
      html: `
  <div style="background-color:#f9fafb; padding:40px 0; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
    <div style="max-width:600px; margin:auto; background:#ffffff; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.05); padding:40px;">
      <h1 style="font-size:24px; color:#2169a8; text-align:center; margin-bottom:24px;">
        Verify your account with ${app_name}
      </h1>

      <p style="font-size:16px; color:#374151; line-height:1.6;">
        Hi there,<br><br>
        Please verify your account using the code below:
      </p>

      <div style="text-align:center; margin:30px 0;">
        <span style="display:inline-block; background:#eef2ff; color:#2169a8; font-size:24px; letter-spacing:4px; font-weight:bold; padding:12px 24px; border-radius:8px;">
          ${token}
        </span>
      </div>

      <p style="font-size:14px; color:#6b7280; line-height:1.6; text-align:center;">
        If you did not initiate this request, you can safely ignore this message.
      </p>

      <hr style="border:none; border-top:1px solid #e5e7eb; margin:30px 0;">

      <p style="font-size:12px; color:#9ca3af; text-align:center;">
        © ${new Date().getFullYear()} ${app_name}. All rights reserved.
      </p>
    </div>
  </div>
  `,
    });

    logger.info('Verification email sent');
  } catch (error) {
    logger.error(`Failed to send verification email ${error}`);
  }
};

export const sendOTPSMS = async (to: string, token: number) => {
  logger.debug(`Sending verification SMS: ${to} with ${token}`);

  if (isDevelopment) {
    return;
  }

  try {
    const { app_name } = await getSystemConfig();
    const body = `Your ${app_name} verification code is: ${token}. No one will ever ask you for this code. DO NOT share it.`;

    if (smsProvider === 'twilio') {
      await sendSmsWithTwilio(to, body);
    } else {
      await sendSmsWithAws(to, body);
    }
  } catch (error) {
    logger.error(`Failed to send verification SMS ${error}`);
  }
};

export const sendMagicLinkEmail = async (to: string, _token: string, safeRedirect: string) => {
  logger.debug(`Sending magic link to: ${to}. URL: ${safeRedirect}`);

  if (isDevelopment) {
    return;
  }

  try {
    const { app_name } = await getSystemConfig();

    await sendEmail({
      to,
      subject: `${app_name} - Your sign-in link`,
      html: `
  <div style="background-color:#f9fafb; padding:40px 0; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
    <div style="max-width:600px; margin:auto; background:#ffffff; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.05); padding:40px;">
      <h1 style="font-size:24px; color:#2169a8; text-align:center; margin-bottom:24px;">
        Sign in to ${app_name}
      </h1>

      <p style="font-size:16px; color:#374151; line-height:1.6;">
        Use the secure link below to complete sign-in:
      </p>

      <div style="text-align:center; margin:30px 0;">
        <a href="${safeRedirect}"
           style="background:#2169a8; color:#ffffff; text-decoration:none; padding:14px 28px; border-radius:8px; font-weight:600; display:inline-block;">
          Open Sign-In Link
        </a>
      </div>

      <p style="font-size:14px; color:#6b7280; line-height:1.6; text-align:center;">
        If the button does not work, copy and paste this URL into your browser:<br>
        <span style="word-break:break-all;">${safeRedirect}</span>
      </p>

      <p style="font-size:14px; color:#6b7280; line-height:1.6; text-align:center;">
        If you did not request this email, you can safely ignore it.
      </p>
    </div>
  </div>
  `,
    });
  } catch (error) {
    logger.error(`Failed to send magic link email ${error}`);
  }
};

export const sendBootstrapEmail = async (to: string, url: string) => {
  logger.debug(`Sending bootsrap invitation email to: ${to}. URL: ${url}`);

  if (isDevelopment) {
    return;
  }

  try {
    const { app_name } = await getSystemConfig();

    await sendEmail({
      to,
      subject: `${app_name} - Bootstrap invite`,
      html: `
  <div style="background-color:#f9fafb; padding:40px 0; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
    <div style="max-width:600px; margin:auto; background:#ffffff; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.05); padding:40px;">
      <h1 style="font-size:24px; color:#2169a8; text-align:center; margin-bottom:24px;">
        Bootstrap invite for ${app_name}
      </h1>

      <p style="font-size:16px; color:#374151; line-height:1.6;">
        Use the link below to continue your bootstrap setup:
      </p>

      <div style="text-align:center; margin:30px 0;">
        <a href="${url}"
           style="background:#2169a8; color:#ffffff; text-decoration:none; padding:14px 28px; border-radius:8px; font-weight:600; display:inline-block;">
          Continue Setup
        </a>
      </div>

      <p style="font-size:14px; color:#6b7280; line-height:1.6; text-align:center;">
        If the button does not work, copy and paste this URL into your browser:<br>
        <span style="word-break:break-all;">${url}</span>
      </p>
    </div>
  </div>
  `,
    });
  } catch (error) {
    logger.error(`Failed to send bootstrap invite email ${error}`);
  }
};
