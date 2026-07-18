import request from 'supertest';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import { createApp } from '../../../src/app.js';
import {
  assertBootstrapAllowed,
  assertBootstrapSecret,
  createAdminBootstrapInvite,
  BootstrapError,
} from '../../../src/services/bootstrapService.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
});

vi.mock('../../../src/services/bootstrapService.js', () => ({
  assertBootstrapAllowed: vi.fn(),
  assertBootstrapSecret: vi.fn(),
  createAdminBootstrapInvite: vi.fn(),
  BootstrapError: class BootstrapError extends Error {
    code: string;
    status: number;
    constructor(code: string, message: string, status: number) {
      super(message);
      this.code = code;
      this.status = status;
    }
  },
}));

it('creates bootstrap invite successfully', async () => {
  (createAdminBootstrapInvite as any).mockResolvedValue({
    registrationUrl:
      'http://localhost:3000/register?bootstrapToken=test-secret-that-is-very-long-very-very-very-long',
    expiresAt: new Date(),
    token: 'test-secret-that-is-very-long-very-very-very-long',
  });

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .set('Authorization', 'Bearer test-secret-that-is-very-long-very-very-very-long')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(201);

  expect(assertBootstrapSecret).toHaveBeenCalledWith(
    'test-secret-that-is-very-long-very-very-very-long',
  );
  expect(assertBootstrapAllowed).toHaveBeenCalled();

  expect(createAdminBootstrapInvite).toHaveBeenCalledWith(
    expect.objectContaining({
      email: 'test@example.com',
    }),
  );

  expect(res.body.success).toBe(true);
  expect(res.body.data.expiresAt).toBeDefined();
  expect(res.body.data.url).toBeUndefined();
  expect(res.body.data.token).toBeUndefined();
});

it('returns bootstrap invite token details only when explicitly requested in non-production', async () => {
  (createAdminBootstrapInvite as any).mockResolvedValue({
    registrationUrl:
      'http://localhost:3000/register?bootstrapToken=test-secret-that-is-very-long-very-very-very-long',
    expiresAt: new Date(),
    token: 'test-secret-that-is-very-long-very-very-very-long',
  });

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .set('Authorization', 'Bearer test-secret-that-is-very-long-very-very-very-long')
    .set('x-seamless-auth-include-sensitive', 'true')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(201);
  expect(res.body.success).toBe(true);
  expect(res.body.data.url).toContain('bootstrapToken');
  expect(res.body.data.token).toBe('test-secret-that-is-very-long-very-very-very-long');
});

it('returns an external delivery payload when requested', async () => {
  (assertBootstrapSecret as any).mockReset();
  (assertBootstrapAllowed as any).mockReset();
  (createAdminBootstrapInvite as any).mockResolvedValue({
    registrationUrl: 'http://localhost:3000/register?bootstrapToken=tok',
    expiresAt: new Date(),
    token: 'test-secret-that-is-very-long-very-very-very-long',
    email: 'test@example.com',
  });

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .set('Authorization', 'Bearer test-secret-that-is-very-long-very-very-very-long')
    .set('x-seamless-auth-delivery-mode', 'external')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(201);
  expect(res.body.data.delivery).toMatchObject({
    kind: 'bootstrap_invite_email',
    to: 'test@example.com',
    inviteUrl: 'http://localhost:3000/register?bootstrapToken=tok',
    token: 'test-secret-that-is-very-long-very-very-very-long',
  });
  expect(createAdminBootstrapInvite).toHaveBeenCalledWith(
    expect.objectContaining({ sendMessage: false }),
  );
});

it('fails when missing bearer token', async () => {
  (assertBootstrapSecret as any).mockImplementation(() => {
    throw new BootstrapError('UNAUTHORIZED', 'Unauthorized', 401);
  });

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(401);
  expect(res.body.success).toBe(false);
});

it('fails when auth header is not bearer', async () => {
  (assertBootstrapSecret as any).mockImplementation(() => {
    throw new BootstrapError('UNAUTHORIZED', 'Unauthorized', 401);
  });

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .set('Authorization', 'Basic abc123')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(401);
});

it('fails when bootstrap not allowed', async () => {
  (assertBootstrapAllowed as any).mockImplementation(() => {
    throw new BootstrapError('BOOTSTRAP_DISABLED', 'Not allowed', 403);
  });

  (assertBootstrapSecret as any).mockImplementation(() => vi.fn());

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .set('Authorization', 'Bearer test-secret-that-is-very-long-very-very-very-long')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(403);
  expect(res.body.error.code).toBe('BOOTSTRAP_DISABLED');
});

it('handles BootstrapError from service', async () => {
  (createAdminBootstrapInvite as any).mockImplementation(() => {
    throw new BootstrapError('FAILED', 'Something went wrong', 400);
  });

  (assertBootstrapAllowed as any).mockImplementation(() => vi.fn());
  (assertBootstrapSecret as any).mockImplementation(() => vi.fn());

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .set('Authorization', 'Bearer test-secret-that-is-very-long-very-very-very-long')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(400);
  expect(res.body.error.code).toBe('FAILED');
});

it('handles unexpected errors', async () => {
  (createAdminBootstrapInvite as any).mockImplementation(() => {
    throw new Error('boom');
  });

  const res = await request(app)
    .post('/internal/bootstrap/admin-invite')
    .set('Authorization', 'Bearer test-secret')
    .send({ email: 'test@example.com' });

  expect(res.status).toBe(500);
  expect(res.body.error.code).toBe('BOOTSTRAP_INTERNAL_ERROR');
});
