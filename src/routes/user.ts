/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import { deleteCredential, deleteUser, getUser, updateCredential } from '../controllers/user';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware';

const router = Router();

router.get('/me', attachAuthMiddleware('access'), getUser);
router.delete('/delete', attachAuthMiddleware('access'), deleteUser);
router.post('/credentials', attachAuthMiddleware('access'), updateCredential);
router.delete('/credentials', attachAuthMiddleware('access'), deleteCredential);

export default router;
