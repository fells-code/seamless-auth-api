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

router.post(
  '/',
  attachAuthMiddleware('ephemeral'),
  magicLinkIpLimiter,
  magicLinkEmailLimiter,
  requestMagicLink,
);

router.get('/poll/:token', attachAuthMiddleware('ephemeral'), pollMagicLinkConfirmation);
router.get('/verify', attachAuthMiddleware('ephemeral'), verifyMagicLink);

export default router;
