import { beforeEach, describe, expect, it, vi } from 'vitest';

const loggerMock = {
  info: vi.fn(),
};

vi.mock('../../../src/utils/logger.js', () => ({
  default: () => loggerMock,
}));

describe('routeLogger', () => {
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    next = vi.fn();
  });

  it('skips logging for GET /health/status', async () => {
    const { logRoute } = await import('../../../src/middleware/routeLogger.js');

    const req = {
      method: 'GET',
      path: '/health/status',
      url: '/health/status',
    } as any;

    logRoute(req, {} as any, next);

    expect(loggerMock.info).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
  });

  it('continues logging other routes', async () => {
    const { logRoute } = await import('../../../src/middleware/routeLogger.js');

    const req = {
      method: 'GET',
      path: '/users/me',
      url: '/users/me',
    } as any;

    logRoute(req, {} as any, next);

    expect(loggerMock.info).toHaveBeenCalledWith('Received GET request for /users/me');
    expect(next).toHaveBeenCalled();
  });
});
