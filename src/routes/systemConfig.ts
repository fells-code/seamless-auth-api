/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import { getSystemConfigHandler, updateSystemConfig } from '../controllers/systemConfig';
import { verifyServiceToken } from '../middleware/authenticateServiceToken';

const router = Router();

router.patch('/:triggeredBy', verifyServiceToken, updateSystemConfig);
router.get('/:triggeredBy', verifyServiceToken, getSystemConfigHandler);

export default router;
