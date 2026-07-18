import { describe, it, expect, vi, beforeEach } from 'vitest';

import {
  isBootstrapEnabled,
  getBootstrapSecret,
  assertBootstrapSecret,
  assertBootstrapAllowed,
  createAdminBootstrapInvite,
  BootstrapError,
  hashBootstrapToken,
} from '../../../src/services/bootstrapService.js';

// ---- mocks ----

vi.mock('../../../src/models/bootstrapInvites.js', () => ({
  BootstrapInvite: {
    findOne: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../src/models/users.js', () => ({
  User: {
    count: vi.fn(),
  },
}));

vi.mock('../../../src/config/getSystemConfig.js', () => ({
  getSystemConfig: vi.fn(),
}));

vi.mock('../../../src/services/messagingService.js', () => ({
  sendBootstrapEmail: vi.fn(),
}));

// ---- imports AFTER mocks ----

import { BootstrapInvite } from '../../../src/models/bootstrapInvites.js';
import { User } from '../../../src/models/users.js';
import { getSystemConfig } from '../../../src/config/getSystemConfig.js';
import { sendBootstrapEmail } from '../../../src/services/messagingService.js';
import getLogger from '../../../src/utils/logger.js';

// ---- setup ----

beforeEach(() => {
  vi.clearAllMocks();

  process.env.SEAMLESS_BOOTSTRAP_ENABLED = 'true';
  process.env.SEAMLESS_BOOTSTRAP_SECRET = 'test-secret';
  process.env.NODE_ENV = 'test';

  (User.count as any).mockResolvedValue(0);
  (BootstrapInvite.findOne as any).mockResolvedValue(null);
  (BootstrapInvite.create as any).mockResolvedValue({});
  (getSystemConfig as any).mockResolvedValue({
    origins: ['http://localhost:3000'],
  });
});

it('returns true when enabled', () => {
  process.env.SEAMLESS_BOOTSTRAP_ENABLED = 'true';
  expect(isBootstrapEnabled()).toBe(true);
});

it('returns false when disabled', () => {
  process.env.SEAMLESS_BOOTSTRAP_ENABLED = 'false';
  expect(isBootstrapEnabled()).toBe(false);
});

it('returns secret when set', () => {
  process.env.SEAMLESS_BOOTSTRAP_SECRET = 'abc';
  expect(getBootstrapSecret()).toBe('abc');
});

it('throws when secret missing', () => {
  delete process.env.SEAMLESS_BOOTSTRAP_SECRET;

  expect(() => getBootstrapSecret()).toThrow(BootstrapError);
});

it('passes when token matches', () => {
  expect(() => assertBootstrapSecret('test-secret')).not.toThrow();
});

it('fails when missing token', () => {
  expect(() => assertBootstrapSecret(undefined)).toThrow(BootstrapError);
});

it('fails when token incorrect', () => {
  expect(() => assertBootstrapSecret('wrong')).toThrow(BootstrapError);
});

it('throws when bootstrap disabled', async () => {
  process.env.SEAMLESS_BOOTSTRAP_ENABLED = 'false';

  await expect(assertBootstrapAllowed()).rejects.toThrow(BootstrapError);
});

it('throws when admin exists', async () => {
  (User.count as any).mockResolvedValue(1);

  await expect(assertBootstrapAllowed()).rejects.toThrow(BootstrapError);
});

it('passes when no admin exists', async () => {
  (User.count as any).mockResolvedValue(0);

  await expect(assertBootstrapAllowed()).resolves.toBeUndefined();
});

it('creates bootstrap invite successfully', async () => {
  const result = await createAdminBootstrapInvite({
    email: 'test@example.com',
  });

  expect(BootstrapInvite.create).toHaveBeenCalled();

  expect(sendBootstrapEmail).toHaveBeenCalledWith(
    'test@example.com',
    expect.stringContaining('bootstrapToken'),
  );

  expect(result.token).toBeDefined();
  expect(result.registrationUrl).toContain('bootstrapToken');
});

it('throws if active invite exists', async () => {
  (BootstrapInvite.findOne as any).mockResolvedValue({
    id: 'existing',
  });

  await expect(
    createAdminBootstrapInvite({
      email: 'test@example.com',
    }),
  ).rejects.toThrow(BootstrapError);
});

it('stores email in lowercase', async () => {
  await createAdminBootstrapInvite({
    email: 'TEST@EXAMPLE.COM',
  });

  expect(BootstrapInvite.create).toHaveBeenCalledWith(
    expect.objectContaining({
      email: 'test@example.com',
    }),
  );
});

it('logs the invite link when debug secrets are enabled in development', async () => {
  process.env.NODE_ENV = 'development';
  process.env.SEAMLESS_AUTH_DEBUG_SECRETS = 'true';

  try {
    const result = await createAdminBootstrapInvite({ email: 'debug@example.com' });

    expect(result.registrationUrl).toContain('bootstrapToken');
    expect(sendBootstrapEmail).toHaveBeenCalled();
  } finally {
    process.env.NODE_ENV = 'test';
    delete process.env.SEAMLESS_AUTH_DEBUG_SECRETS;
  }
});

it('skips sending the invite email when sendMessage is false', async () => {
  const result = await createAdminBootstrapInvite({
    email: 'silent@example.com',
    sendMessage: false,
  });

  expect(BootstrapInvite.create).toHaveBeenCalled();
  expect(sendBootstrapEmail).not.toHaveBeenCalled();
  expect(result.token).toBeDefined();
});

it('hashes token consistently', () => {
  const hash1 = hashBootstrapToken('abc');
  const hash2 = hashBootstrapToken('abc');

  expect(hash1).toBe(hash2);
});

it('produces different hashes for different tokens', () => {
  const hash1 = hashBootstrapToken('abc');
  const hash2 = hashBootstrapToken('def');

  expect(hash1).not.toBe(hash2);
});
