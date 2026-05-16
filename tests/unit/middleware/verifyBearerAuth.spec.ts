import { describe, it, expect, vi, beforeEach } from 'vitest';

import { verifyBearerAuth } from '../../../src/middleware/verifyBearerAuth';
import { validateBearerToken } from '../../../src/services/sessionService';

vi.mock('../../../src/services/sessionService', () => ({
  validateBearerToken: vi.fn(),
}));

describe('verifyBearerAuth', () => {
  let req: any;
  let res: any;
  let next: any;

  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      headers: {},
    };

    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };

    next = vi.fn();
  });

  it('returns 401 if no authorization header', async () => {
    await verifyBearerAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'missing bearer token',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 if not Bearer format', async () => {
    req.headers.authorization = 'Basic abc';

    await verifyBearerAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 401 if token is invalid', async () => {
    req.headers.authorization = 'Bearer token';

    (validateBearerToken as any).mockResolvedValue(null);

    await verifyBearerAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'unauthorized',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it('attaches user and calls next', async () => {
    req.headers.authorization = 'Bearer token';

    const mockUser = { id: 'user-1' };

    (validateBearerToken as any).mockResolvedValue({
      user: mockUser,
      sessionId: 'session-1',
    });

    await verifyBearerAuth(req, res, next);

    expect(req.user).toEqual(mockUser);
    expect(req.sessionId).toBe('session-1');
    expect(next).toHaveBeenCalled();
  });

  it('returns 401 if validation throws', async () => {
    req.headers.authorization = 'Bearer token';

    (validateBearerToken as any).mockRejectedValue(new Error('boom'));

    await verifyBearerAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'unauthorized',
    });
    expect(next).not.toHaveBeenCalled();
  });
});
