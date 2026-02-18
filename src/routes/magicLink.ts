/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import { requestMagicLink, verifyMagicLink } from '../controllers/magicLinks';
import { magicLinkEmailLimiter, magicLinkIpLimiter } from '../middleware/rateLimit';

const router = Router();

router.post('/', magicLinkIpLimiter, magicLinkEmailLimiter, requestMagicLink);

router.get('/verify', verifyMagicLink);

export default router;
