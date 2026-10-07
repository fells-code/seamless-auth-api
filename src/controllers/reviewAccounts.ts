/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { ReviewAccountsQuerySchema } from '../schemas/reviewAccounts.js';
import { getReviewAccounts } from '../services/reviewAccountUsage.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('reviewAccounts');

export async function getReviewAccountStatus(req: Request, res: Response) {
  // Re-parsed so the default is typed; `defineRoute` has already validated the query.
  const query = ReviewAccountsQuerySchema.parse(req.query);

  try {
    return res.json(await getReviewAccounts(query));
  } catch (error) {
    logger.error(`Failed to read review account usage: ${error}`);
    return res.status(500).json({ error: 'Failed to read review account usage' });
  }
}
