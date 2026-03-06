/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import {
  pollMagicLinkConfirmation,
  requestMagicLink,
  verifyMagicLink,
} from '../controllers/magicLinks';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware';
import { magicLinkEmailLimiter, magicLinkIpLimiter } from '../middleware/rateLimit';

const router = Router();

router.get(
  '/',
  attachAuthMiddleware('ephemeral'),
  magicLinkIpLimiter,
  magicLinkEmailLimiter,
  requestMagicLink,
);

router.get('/poll', attachAuthMiddleware('ephemeral'), pollMagicLinkConfirmation);
router.get('/verify/:token', verifyMagicLink);

export default router;
