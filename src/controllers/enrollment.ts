/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { wantsExternalDelivery } from '../lib/externalDelivery.js';
import {
  AdminEnrollmentQuerySchema,
  EnrollmentInviteRequestSchema,
} from '../schemas/enrollment.js';
import { AuthEventService } from '../services/authEventService.js';
import {
  EnrollmentInviteError,
  inviteToEnroll,
  listEnrollment,
} from '../services/enrollmentService.js';
import { AuthenticatedRequest } from '../types/types.js';

export async function getEnrollment(req: Request, res: Response) {
  // Re-parsed so the coerced numbers and booleans recover their types; `defineRoute`
  // has already validated the query, so this cannot fail.
  const query = AdminEnrollmentQuerySchema.parse(req.query);

  return res.json(await listEnrollment(query));
}

export async function sendEnrollmentInvites(req: Request, res: Response) {
  const request = EnrollmentInviteRequestSchema.parse(req.body);

  // The invite carries no secret (it links to the sign-in page), so external delivery
  // needs no service token here, unlike a code or a magic link. That is what lets an
  // organization send invites from its own mail system.
  const external = wantsExternalDelivery(req);

  try {
    const { invitedUserIds, ...response } = await inviteToEnroll(request, { external });
    const actorUserId = (req as AuthenticatedRequest).user?.id ?? null;

    for (const userId of invitedUserIds) {
      await AuthEventService.log({
        userId,
        actorUserId,
        type: 'admin_enrollment_invite_sent',
        req,
        metadata: {
          external,
          ...(request.organizationId ? { organizationId: request.organizationId } : {}),
        },
      });
    }

    return res.json(response);
  } catch (error) {
    if (error instanceof EnrollmentInviteError) {
      return res.status(error.status).json({ error: error.message });
    }
    throw error;
  }
}
