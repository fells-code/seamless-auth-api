/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import { Router } from 'express';

import {
  sendEmailOTP,
  sendPhoneOTP,
  verifyEmail,
  verifyLoginEmail,
  verifyLoginPhoneNumber,
  verifyPhoneNumber,
} from '../controllers/otp';
import { attachAuthMiddleware } from '../middleware/attachAuthMiddleware';

const router = Router();

router.get('/generate-email-otp', attachAuthMiddleware('ephemeral'), sendEmailOTP);
router.get('/generate-phone-otp', attachAuthMiddleware('ephemeral'), sendPhoneOTP);
router.post('/verify-email-otp', attachAuthMiddleware('ephemeral'), verifyEmail);
router.post(
  '/verify-phone-otp',

  attachAuthMiddleware('ephemeral'),
  verifyPhoneNumber,
);
router.get(
  '/generate-login-email-otp',

  attachAuthMiddleware('ephemeral'),
  sendEmailOTP,
);
router.get(
  '/generate-login-phone-otp',

  attachAuthMiddleware('ephemeral'),
  sendPhoneOTP,
);
router.post(
  '/verify-login-email-otp',

  attachAuthMiddleware('ephemeral'),
  verifyLoginEmail,
);
router.post(
  '/verify-login-phone-otp',

  attachAuthMiddleware('ephemeral'),
  verifyLoginPhoneNumber,
);

export default router;
