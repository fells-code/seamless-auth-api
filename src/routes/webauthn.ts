/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import {
  generateWebAuthn,
  registerWebAuthn,
  verifyWebAuthn,
  verifyWebAuthnRegistration,
} from '../controllers/webauthn';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware';

const router = Router();

router.get('/register/start', attachAuthMiddleware('ephemeral'), registerWebAuthn);
router.post(
  '/register/finish',

  attachAuthMiddleware('ephemeral'),
  verifyWebAuthnRegistration,
);
router.post('/login/start', attachAuthMiddleware('ephemeral'), generateWebAuthn);
router.post('/login/finish', attachAuthMiddleware('ephemeral'), verifyWebAuthn);

export default router;
