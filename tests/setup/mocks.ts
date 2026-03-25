import { vi } from 'vitest';

vi.mock('../../../src/models/authEvents.js', () => ({
  AuthEvent: {
    create: vi.fn(),
  },
}));

vi.mock('../../src/models/sessions.js', () => ({
  Session: {
    create: vi.fn(),
    findAll: vi.fn(),
    findOne: vi.fn(),
  },
}));

vi.mock('../../src/middleware/attachAuthMiddleware.js', () => ({
  attachAuthMiddleware: () => (req: any, _res: any, next: any) => {
    // inject fake authenticated user
    req.user = {
      id: 'user-1',
      email: 'test@example.com',
      phone: '+14155552671',
      roles: ['user'],

      // required for verification flows
      emailVerificationToken: '123456',
      emailVerificationTokenExpiry: new Date(Date.now() + 100000),

      phoneVerificationToken: '123456',
      phoneVerificationTokenExpiry: new Date(Date.now() + 100000),

      verified: true,
      emailVerified: true,
      phoneVerified: true,

      update: vi.fn(),
    };
    next();
  },
}));

vi.mock('../../src/utils/otp.js', () => ({
  generatePhoneOTP: vi.fn(),
  generateEmailOTP: vi.fn(),
  verifyPhoneOTP: vi.fn(),
  verifyEmailOTP: vi.fn(),
}));

vi.mock('../../src/lib/token.js', () => ({
  signEphemeralToken: vi.fn(),
  signAccessToken: vi.fn(),
  generateRefreshToken: vi.fn(),
  hashRefreshToken: vi.fn(),
}));
