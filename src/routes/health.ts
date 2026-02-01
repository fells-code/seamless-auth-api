/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import { healthCheck, version } from '../controllers/health';

const router = Router();

router.get('/status', healthCheck);
router.get('/version', version);

export default router;
