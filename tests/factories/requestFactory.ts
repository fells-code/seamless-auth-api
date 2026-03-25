export function buildRegistrationRequest(overrides = {}) {
  return {
    email: 'test@example.com',
    phone: '+14155552671', // ✅ VALID
    ...overrides,
  };
}
