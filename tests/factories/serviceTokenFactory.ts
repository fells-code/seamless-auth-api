export const TRUSTED_SERVICE_TOKEN = 'trusted-internal-service-token';

/**
 * External delivery requires a validated internal service token in every environment. The
 * suite mocks the service-token middleware globally, so this stubs the validator to accept
 * TRUSTED_SERVICE_TOKEN and reject anything else, and returns the value to send in the
 * x-seamless-service-token header.
 *
 * The module is imported at call time because specs that use vi.resetModules() would
 * otherwise stub a stale copy of the mock.
 */
export async function mintInternalServiceToken(claims: Record<string, unknown> = {}) {
  const { validateInternalServiceToken } =
    await import('../../src/middleware/authenticateServiceToken.js');

  (
    validateInternalServiceToken as unknown as {
      mockImplementation: (fn: (token: string) => unknown) => void;
    }
  ).mockImplementation((token: string) =>
    token === TRUSTED_SERVICE_TOKEN
      ? { sub: 'test-service', iss: 'seamless-portal-api', aud: 'seamless-auth', ...claims }
      : null,
  );

  return TRUSTED_SERVICE_TOKEN;
}
