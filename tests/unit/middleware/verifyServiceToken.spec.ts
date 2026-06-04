import { describe, it, expect, vi, beforeEach } from 'vitest';
import { verifyServiceToken } from '../../../src/middleware/authenticateServiceToken';

vi.unmock('../../../src/middleware/authenticateServiceToken');
vi.mock('jsonwebtoken', () => ({
  default: {
    decode: vi.fn(() => ({ header: { alg: 'HS256' } })),
    verify: vi.fn(),
  },
}));

vi.mock('../../../src/utils/secretsStore', () => ({
  getSecret: vi.fn().mockResolvedValue('secret'),
}));

describe('verifyServiceToken', () => {
  let req: any;
  let res: any;
  let next: any;

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    req = {
      headers: {},
      params: {},
    };

    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };

    next = vi.fn();
  });

  it('rejects malformed header', async () => {
    await verifyServiceToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Malformed authorization header',
    });
  });

  it('rejects missing token', async () => {
    req.headers.authorization = 'Bearer ';

    const { verifyServiceToken } = await import('../../../src/middleware/authenticateServiceToken');

    await verifyServiceToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('rejects when secret missing', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');

    (getSecret as any).mockResolvedValue(null);

    req.headers.authorization = 'Bearer token';

    const { verifyServiceToken } = await import('../../../src/middleware/authenticateServiceToken');

    await verifyServiceToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('rejects invalid issuer', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');
    const jwt = await import('jsonwebtoken');

    (getSecret as any).mockResolvedValue('secret');

    (jwt.default.verify as any).mockReturnValue({
      iss: 'wrong',
      aud: 'seamless-auth',
      sub: 'client',
    });

    req.headers.authorization = 'Bearer token';

    const { verifyServiceToken } = await import('../../../src/middleware/authenticateServiceToken');

    await verifyServiceToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('rejects invalid audience', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');
    const jwt = await import('jsonwebtoken');

    (getSecret as any).mockResolvedValue('secret');

    (jwt.default.verify as any).mockReturnValue({
      iss: 'seamless-portal-api',
      aud: 'wrong',
      sub: 'client',
    });

    req.headers.authorization = 'Bearer token';

    const { verifyServiceToken } = await import('../../../src/middleware/authenticateServiceToken');

    await verifyServiceToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('attaches clientId and calls next', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');
    const jwt = await import('jsonwebtoken');

    (getSecret as any).mockResolvedValue('secret');

    (jwt.default.verify as any).mockReturnValue({
      iss: 'seamless-portal-api',
      aud: 'seamless-auth',
      sub: 'client-1',
    });

    req.headers.authorization = 'Bearer token';
    req.params.triggeredBy = 'admin';

    const { verifyServiceToken } = await import('../../../src/middleware/authenticateServiceToken');

    await verifyServiceToken(req, res, next);

    expect(req.clientId).toBe('client-1');
    expect(req.triggeredBy).toBe('admin');
    expect(next).toHaveBeenCalled();
  });

  it('returns 401 if jwt throws', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');
    const jwt = await import('jsonwebtoken');

    (getSecret as any).mockResolvedValue('secret');

    (jwt.default.verify as any).mockImplementation(() => {
      throw new Error('invalid');
    });

    req.headers.authorization = 'Bearer token';

    const { verifyServiceToken } = await import('../../../src/middleware/authenticateServiceToken');

    await verifyServiceToken(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('rejects RS256 user JWTs without attempting internal service verification', async () => {
    const { getSecret } = await import('../../../src/utils/secretsStore');
    const jwt = await import('jsonwebtoken');

    (getSecret as any).mockResolvedValue('secret');
    (jwt.default.decode as any).mockReturnValue({
      header: { alg: 'RS256' },
    });

    const { validateInternalServiceToken } =
      await import('../../../src/middleware/authenticateServiceToken');

    await expect(validateInternalServiceToken('user-jwt')).resolves.toBeNull();

    expect(jwt.default.verify).not.toHaveBeenCalled();
  });
});
