import request from 'supertest';
import { createApp } from '../../../src/app';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Application } from 'express';

import {
  recordAuditWriteFailure,
  resetAuditHealthForTests,
} from '../../../src/services/auditHealth.js';
import { AuthEventService } from '../../../src/services/authEventService.js';

let app: Application;

beforeAll(async () => {
  app = await createApp();
});

beforeEach(() => {
  vi.clearAllMocks();
  resetAuditHealthForTests();
});

describe('Health Routes', () => {
  it('returns system status', async () => {
    const res = await request(app).get('/health/status');

    expect(res.status).toBe(200);
    // The healthy body is unchanged, so anything already parsing it is unaffected.
    expect(res.body).toEqual({ message: 'System up' });
  });

  // NIST 800-53 AU-5 wants a defined action when audit logging fails. Reporting
  // it where monitoring already looks is that action; a log line nobody reads is
  // not.
  it('reports degraded when audit writes are failing', async () => {
    recordAuditWriteFailure(new Error('disk full'));

    const res = await request(app).get('/health/status');

    // Still 200: the service is serving requests and should not be pulled out of
    // a load balancer for this.
    expect(res.status).toBe(200);
    expect(res.body.message).toBe('System up, audit degraded');
    expect(res.body.degraded.audit.failureCount).toBe(1);
    expect(res.body.degraded.audit.lastFailureAt).toEqual(expect.any(String));
  });

  it('returns the API version', async () => {
    const res = await request(app).get('/health/version');

    expect(res.status).toBe(200);
    expect(typeof res.body.message).toBe('string');
    expect(res.body.message.length).toBeGreaterThan(0);
  });

  it('returns 404 for unknown health route', async () => {
    const res = await request(app).get('/health/unknown');

    expect(res.status).toBe(404);
    expect(AuthEventService.requestSuspicious).toHaveBeenCalledWith(
      expect.objectContaining({
        originalUrl: '/health/unknown',
      }),
      expect.objectContaining({
        reason: 'Request to an unknown route.',
        path: '/health/unknown',
      }),
    );
  });
});
