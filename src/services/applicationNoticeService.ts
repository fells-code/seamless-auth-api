/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import type { MessagingChannel, SendApplicationNoticeRequest } from '@seamless-auth/types';

import type { OidcClient } from '../models/oidcClients.js';
import { User } from '../models/users.js';
import {
  type AccountNotice,
  type AccountNoticeOutcome,
  sendAccountNotice,
  verifiedAddresses,
} from './accountNotices.js';
import { hasOidcGrantForUser } from './oidcPayloadStore.js';

export class ApplicationNoticeError extends Error {
  constructor(
    readonly status: number,
    readonly code: 'notice_unknown_user' | 'notice_no_channel' | 'notice_action_url_not_allowed',
  ) {
    super(code);
  }
}

function singleLine(value: string) {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
}

/** Only the https origins the client registered redirects on: never loopback or private-use. */
function registeredOrigins(client: OidcClient) {
  return new Set(
    client.redirectUris.flatMap((uri) => {
      const url = new URL(uri);
      return url.protocol === 'https:' ? [url.origin] : [];
    }),
  );
}

export function actionUrlAllowed(client: OidcClient, actionUrl: string) {
  const url = new URL(actionUrl);
  return (
    url.protocol === 'https:' &&
    !url.username &&
    !url.password &&
    registeredOrigins(client).has(url.origin)
  );
}

/**
 * The fixed template (ADR 0001, D14). The application supplies only the subject line and
 * the body; the attribution is the API's, so a notice cannot read as one from Seamless.
 */
export function applicationNotice(
  client: OidcClient,
  instanceName: string,
  {
    subject,
    text,
    actionUrl,
  }: Pick<SendApplicationNoticeRequest, 'subject' | 'text' | 'actionUrl'>,
): AccountNotice {
  const application = singleLine(client.name);
  const instance = singleLine(instanceName);
  const body = [text, ...(actionUrl ? [actionUrl] : [])].join('\n\n');

  return {
    name: 'application_notice',
    subject: `[${application}] ${singleLine(subject)}`,
    text: `${body}\n\n--\nSent by ${application} through ${instance}.`,
    application: { clientId: client.id, name: client.name },
  };
}

/**
 * Sends a notice on the client's behalf to a user who holds a grant with it. A user that
 * does not exist and one with no grant answer the same, so a client cannot probe for
 * accounts it has no relationship with.
 */
export async function sendApplicationNotice(
  client: OidcClient,
  instanceName: string,
  request: SendApplicationNoticeRequest,
  delivery: { external: boolean; returnable?: ReadonlySet<string> },
): Promise<{ userId: string; outcome: AccountNoticeOutcome }> {
  if (request.actionUrl && !actionUrlAllowed(client, request.actionUrl)) {
    throw new ApplicationNoticeError(400, 'notice_action_url_not_allowed');
  }

  const user = await User.findByPk(request.userId);
  if (!user || user.revoked || !(await hasOidcGrantForUser(user.id, client.id))) {
    throw new ApplicationNoticeError(404, 'notice_unknown_user');
  }

  const wanted = new Set<MessagingChannel>(request.channels ?? ['email', 'sms']);
  const verified = verifiedAddresses(user);
  const recipient = {
    email: wanted.has('email') ? verified.email : null,
    emailVerified: true,
    phone: wanted.has('sms') ? verified.phone : null,
    phoneVerified: true,
  };

  if (!recipient.email && !recipient.phone) {
    throw new ApplicationNoticeError(422, 'notice_no_channel');
  }

  const outcome = await sendAccountNotice(
    recipient,
    applicationNotice(client, instanceName, request),
    delivery,
  );

  return { userId: user.id, outcome };
}
