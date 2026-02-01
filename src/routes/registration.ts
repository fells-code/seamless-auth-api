/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import { register } from '../controllers/registration';

const router = Router();

router.post('/register', register);

export default router;
