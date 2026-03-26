import { vi } from 'vitest';

vi.mock('../../src/models/authEvents.js', () => ({
  AuthEvent: {
    create: vi.fn(),
  },
}));

vi.mock('../../src/models/systemConfig.js', () => ({
  SystemConfig: {
    findAll: vi.fn(),
    upsert: vi.fn(),
    sequelize: {
      transaction: vi.fn((fn: any) => fn({})),
    },
  },
}));

vi.mock('../../src/models/credentials.js', () => ({
  Credential: {
    findAll: vi.fn(),
    findOne: vi.fn(),
    count: vi.fn(),
  },
}));

vi.mock('../../src/models/sessions.js', () => ({
  Session: {
    create: vi.fn(),
    findAll: vi.fn(),
    findOne: vi.fn(),
  },
}));

vi.mock('../../src/models/users.js', () => ({
  User: {
    create: vi.fn(),
    findOne: vi.fn(),
    findByPk: vi.fn(),
    findAll: vi.fn(),
  },
}));

vi.mock('../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
  invalidateSystemConfigCache: vi.fn(),
}));

vi.mock('../../src/services/sessionService.js', () => ({
  validateAccessToken: vi.fn(),
  validateSessionRecord: vi.fn(),
  getUserFromSession: vi.fn(),
  verifyJwtWithKid: vi.fn(),
  revokeSessionChain: vi.fn(),
  hardRevokeSession: vi.fn(),
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

    req.sessionId = 'session-1';
    next();
  },
}));

vi.mock('../../src/middleware/authenticateServiceToken.js', () => ({
  verifyServiceToken: (_req: any, _res: any, next: any) => {
    next();
  },
}));

vi.mock('../../src/middleware/requireAdmin.js', () => ({
  requireAdmin: () => (_req: any, _res: any, next: any) => {
    next();
  },
}));

vi.mock('../../src/middleware/rateLimit.js', () => ({
  magicLinkIpLimiter: (_req: any, _res: any, next: any) => next(),
  magicLinkEmailLimiter: (_req: any, _res: any, next: any) => next(),
  dynamicRateLimit: (_req: any, _res: any, next: any) => next(),
  dynamicSlowDown: (_req: any, _res: any, next: any) => next(),
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

vi.mock('../../src/lib/cookie.js', () => ({
  setAuthCookies: vi.fn(),
  clearAuthCookies: vi.fn(),
}));

vi.mock('bcrypt-ts', () => ({
  compareSync: vi.fn(),
}));

vi.mock('../../src/services/authEventService.js', () => ({
  AuthEventService: {
    log: vi.fn(),
    notificationSent: vi.fn(),
    serviceTokenInvalid: vi.fn(),
  },
}));

vi.mock('../../src/models/magicLinks.js', () => ({
  MagicLinkToken: {
    create: vi.fn(),
    findOne: vi.fn(),
    update: vi.fn(),
  },
}));

vi.mock('../../src/services/messagingService.js', () => ({
  sendMagicLinkEmail: vi.fn(),
}));

vi.mock('crypto', async () => {
  const actual = await vi.importActual<typeof import('crypto')>('crypto');
  return {
    ...actual,
    randomBytes: vi.fn(() => ({
      toString: () => 'mock-token',
    })),
  };
});

vi.mock('../../src/utils/utils.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/utils/utils.js')>(
    '../../src/utils/utils.js',
  );

  return {
    ...actual,
    hashDeviceFingerprint: vi.fn(() => ({
      ip_hash: 'ip',
      user_agent_hash: 'ua',
    })),
  };
});
