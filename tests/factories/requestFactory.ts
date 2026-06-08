export function buildRegistrationRequest(overrides = {}) {
  return {
    email: 'test@example.com',
    ...overrides,
  };
}
