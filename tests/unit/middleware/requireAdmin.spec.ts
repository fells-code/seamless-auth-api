import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.unmock('../../../src/middleware/requireAdmin');
describe('requireAdmin', () => {
  let req: any;
  let res: any;
  let next: any;

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    req = {};
    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    next = vi.fn();
  });

  it('returns 401 if no clientId', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Unauthorized',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 if no user', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin();

    req.clientId = 'client-1';

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 403 if user is not admin', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin();

    req.clientId = 'client-1';
    req.user = {
      id: 'user-1',
      roles: ['user'],
    };

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Forbidden',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next for admin user', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin();

    req.clientId = 'client-1';
    req.user = {
      id: 'user-1',
      roles: ['admin'],
    };

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('calls next for admin read user on read routes', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin('read');

    req.clientId = 'client-1';
    req.user = {
      id: 'user-1',
      roles: ['admin:read'],
    };

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('allows admin write users on read routes', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin('read');

    req.clientId = 'client-1';
    req.user = {
      id: 'user-1',
      roles: ['admin:write'],
    };

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('rejects admin read users on write routes', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin('write');

    req.clientId = 'client-1';
    req.user = {
      id: 'user-1',
      roles: ['admin:read'],
    };

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 500 if unexpected error occurs', async () => {
    const { requireAdmin } = await import('../../../src/middleware/requireAdmin');

    const middleware = requireAdmin();

    req.clientId = 'client-1';

    // force crash
    req.user = {
      get roles() {
        throw new Error('boom');
      },
    };

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Internal server error',
    });
  });
});
