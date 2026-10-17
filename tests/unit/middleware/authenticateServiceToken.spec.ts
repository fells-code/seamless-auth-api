import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.unmock('../../../src/middleware/authenticateServiceToken');
vi.mock('jsonwebtoken', () => ({
  default: {
    decode: vi.fn(() => ({ header: { alg: 'HS256' } })),
    verify: vi.fn(),
  },
}));

vi.mock('../../../src/config/serviceToken', () => ({
  getServiceToken: vi.fn(() => 'secret'),
}));

// clearAllMocks() drops the default implementations, so each load reinstates the
// happy-path secret and HS256 header that most cases start from.
async function load() {
  const { getServiceToken } = await import('../../../src/config/serviceToken');
  const jwt = await import('jsonwebtoken');

  (getServiceToken as any).mockReturnValue('secret');
  (jwt.default.decode as any).mockReturnValue({ header: { alg: 'HS256' } });

  const { validateInternalServiceToken } =
    await import('../../../src/middleware/authenticateServiceToken');

  return { getServiceToken: getServiceToken as any, jwt, validateInternalServiceToken };
}

const inOneMinute = () => Math.floor(Date.now() / 1000) + 60;

describe('validateInternalServiceToken', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('returns null when no token is supplied', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    await expect(validateInternalServiceToken('')).resolves.toBeNull();

    expect(jwt.default.verify).not.toHaveBeenCalled();
  });

  it('returns null when the internal secret is unavailable', async () => {
    const { getServiceToken, jwt, validateInternalServiceToken } = await load();

    getServiceToken.mockReturnValue(undefined);

    await expect(validateInternalServiceToken('token')).resolves.toBeNull();

    expect(jwt.default.verify).not.toHaveBeenCalled();
  });

  it('returns null when the service token env vars conflict', async () => {
    const { getServiceToken, jwt, validateInternalServiceToken } = await load();

    getServiceToken.mockImplementation(() => {
      throw new Error(
        'SEAMLESS_SERVICE_TOKEN and API_SERVICE_TOKEN are both set to different values.',
      );
    });

    await expect(validateInternalServiceToken('token', { logInvalid: true })).resolves.toBeNull();

    expect(jwt.default.verify).not.toHaveBeenCalled();
  });

  it('returns the decoded payload for a valid HS256 token', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    const exp = inOneMinute();
    (jwt.default.verify as any).mockReturnValue({
      iss: 'seamless-portal-api',
      aud: 'seamless-auth',
      sub: 'client-1',
      exp,
    });

    await expect(validateInternalServiceToken('token')).resolves.toEqual({
      iss: 'seamless-portal-api',
      aud: 'seamless-auth',
      sub: 'client-1',
      exp,
    });
  });

  // jsonwebtoken only checks exp when it is present, so a token minted without one
  // would never expire.
  it('rejects a token with no expiry', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.verify as any).mockReturnValue({ sub: 'client-1' });

    await expect(validateInternalServiceToken('token', { logInvalid: true })).resolves.toBeNull();
  });

  it('rejects a token that is good for more than an hour', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.verify as any).mockReturnValue({
      sub: 'client-1',
      exp: Math.floor(Date.now() / 1000) + 2 * 60 * 60,
    });

    await expect(validateInternalServiceToken('token')).resolves.toBeNull();
  });

  it('accepts a token good for an hour, as the conformance harness mints', async () => {
    const { jwt, validateInternalServiceToken } = await load();
    const exp = Math.floor(Date.now() / 1000) + 60 * 60;

    (jwt.default.verify as any).mockReturnValue({ sub: 'client-1', exp });

    await expect(validateInternalServiceToken('token')).resolves.toEqual({ sub: 'client-1', exp });
  });

  it('rejects and logs unsupported-algorithm tokens when logging is enabled', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.decode as any).mockReturnValue({ header: { alg: 'RS256' } });

    await expect(validateInternalServiceToken('token', { logInvalid: true })).resolves.toBeNull();

    expect(jwt.default.verify).not.toHaveBeenCalled();
  });

  it('rejects RS256 user JWTs without attempting internal service verification', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.decode as any).mockReturnValue({ header: { alg: 'RS256' } });

    await expect(validateInternalServiceToken('user-jwt')).resolves.toBeNull();

    expect(jwt.default.verify).not.toHaveBeenCalled();
  });

  it('verifies tokens whose algorithm cannot be decoded from the header', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.decode as any).mockReturnValue(null);
    (jwt.default.verify as any).mockReturnValue({ sub: 'client-2', exp: inOneMinute() });

    await expect(validateInternalServiceToken('token')).resolves.toEqual(
      expect.objectContaining({ sub: 'client-2' }),
    );

    expect(jwt.default.verify).toHaveBeenCalled();
  });

  it('verifies tokens whose header carries a non-string algorithm', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.decode as any).mockReturnValue({ header: { alg: 123 } });
    (jwt.default.verify as any).mockReturnValue({ sub: 'client-3', exp: inOneMinute() });

    await expect(validateInternalServiceToken('token')).resolves.toEqual(
      expect.objectContaining({ sub: 'client-3' }),
    );

    expect(jwt.default.verify).toHaveBeenCalled();
  });

  it('logs and returns null when verification throws with logging enabled', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.verify as any).mockImplementation(() => {
      throw new Error('expired');
    });

    await expect(validateInternalServiceToken('token', { logInvalid: true })).resolves.toBeNull();
  });

  it('returns null without logging when verification throws and logging is disabled', async () => {
    const { jwt, validateInternalServiceToken } = await load();

    (jwt.default.verify as any).mockImplementation(() => {
      throw new Error('expired');
    });

    await expect(validateInternalServiceToken('token')).resolves.toBeNull();
  });

  it('reuses the cached internal secret across calls', async () => {
    const { getServiceToken, jwt, validateInternalServiceToken } = await load();

    (jwt.default.verify as any).mockReturnValue({ sub: 'client' });

    await validateInternalServiceToken('token');
    await validateInternalServiceToken('token');

    expect(getServiceToken).toHaveBeenCalledTimes(1);
  });
});
