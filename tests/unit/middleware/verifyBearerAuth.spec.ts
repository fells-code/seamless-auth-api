import { describe, it, expect, vi, beforeEach } from 'vitest';

import { verifyBearerAuth } from '../../../src/middleware/verifyBearerAuth';
import { AuthEventService } from '../../../src/services/authEventService';
import { validateBearerToken, verifyJwtWithKid } from '../../../src/services/sessionService';

vi.mock('../../../src/services/sessionService', () => ({
  validateBearerToken: vi.fn(),
  verifyJwtWithKid: vi.fn(),
}));

vi.mock('../../../src/services/authEventService', () => ({
  AuthEventService: {
    log: vi.fn(),
  },
}));

function bearerOfType(typ: string, sub = 'user-1') {
  const claims = Buffer.from(JSON.stringify({ typ, sub })).toString('base64url');

  return `Bearer header.${claims}.signature`;
}

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
    expect(validateBearerToken).toHaveBeenCalledWith('token', 'access');
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

    expect(validateBearerToken).toHaveBeenCalledWith('token', 'access');
    expect(req.user).toEqual(mockUser);
    expect(req.sessionId).toBe('session-1');
    expect(next).toHaveBeenCalled();
  });

  it('attaches the organization id when present on the validated result', async () => {
    req.headers.authorization = 'Bearer token';

    const mockUser = { id: 'user-1' };

    (validateBearerToken as any).mockResolvedValue({
      user: mockUser,
      sessionId: 'session-1',
      organizationId: 'org-1',
    });

    await verifyBearerAuth(req, res, next);

    expect(req.organizationId).toBe('org-1');
    expect(req.sessionId).toBe('session-1');
    expect(next).toHaveBeenCalled();
  });

  it('validates with the requested auth token type', async () => {
    req.headers.authorization = 'Bearer token';

    const mockUser = { id: 'user-1' };

    (validateBearerToken as any).mockResolvedValue({
      user: mockUser,
    });

    await verifyBearerAuth(req, res, next, 'ephemeral');

    expect(validateBearerToken).toHaveBeenCalledWith('token', 'ephemeral');
    expect(req.user).toEqual(mockUser);
    expect(req.sessionId).toBeUndefined();
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

  describe('auditing a refused bearer', () => {
    it('records the misuse when a token this issuer minted is presented at another gate', async () => {
      req.headers.authorization = bearerOfType('ephemeral');
      req.baseUrl = '/webauthn';
      req.route = { path: '/register/start' };

      (validateBearerToken as any).mockResolvedValue(null);
      (verifyJwtWithKid as any).mockResolvedValue({ typ: 'ephemeral', sub: 'user-1' });

      await verifyBearerAuth(req, res, next);

      expect(AuthEventService.log).toHaveBeenCalledWith({
        type: 'bearer_token_failed',
        req,
        metadata: {
          reason: 'wrong_token_type',
          expected: 'access',
          presented: 'ephemeral',
          route: '/webauthn/register/start',
          subject: 'user-1',
        },
      });
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
    });

    it('falls back to the request path when no route pattern matched', async () => {
      req.headers.authorization = bearerOfType('access');
      req.path = '/users/me';

      (validateBearerToken as any).mockResolvedValue(null);
      (verifyJwtWithKid as any).mockResolvedValue({ typ: 'access', sub: 'user-1' });

      await verifyBearerAuth(req, res, next, 'ephemeral');

      expect(AuthEventService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({ route: '/users/me', presented: 'access' }),
        }),
      );
    });

    it('records nothing for an ordinary refusal of the expected token type', async () => {
      req.headers.authorization = bearerOfType('access');

      (validateBearerToken as any).mockResolvedValue(null);

      await verifyBearerAuth(req, res, next);

      expect(AuthEventService.log).not.toHaveBeenCalled();
      expect(verifyJwtWithKid).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('records nothing when the refused token does not verify', async () => {
      req.headers.authorization = bearerOfType('ephemeral');

      (validateBearerToken as any).mockResolvedValue(null);
      (verifyJwtWithKid as any).mockResolvedValue(null);

      await verifyBearerAuth(req, res, next);

      expect(AuthEventService.log).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it('still answers 401 when the audit write throws', async () => {
      req.headers.authorization = bearerOfType('ephemeral');

      (validateBearerToken as any).mockResolvedValue(null);
      (verifyJwtWithKid as any).mockResolvedValue({ typ: 'ephemeral', sub: 'user-1' });
      (AuthEventService.log as any).mockRejectedValue(new Error('audit down'));

      await verifyBearerAuth(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'unauthorized' });
      expect(next).not.toHaveBeenCalled();
    });
  });
});
