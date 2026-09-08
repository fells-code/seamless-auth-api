import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.unmock('../../../src/models/authEvents.js');
vi.unmock('../../../src/models/authFailures.js');
vi.unmock('../../../src/models/sessions.js');
vi.unmock('../../../src/models/users.js');
vi.unmock('../../../src/models/systemConfig.js');
vi.unmock('../../../src/models/credentials.js');
vi.unmock('../../../src/models/totpCredentials.js');
vi.unmock('../../../src/models/magicLinks.js');
vi.unmock('../../../src/models/oauthIdentities.js');
vi.unmock('../../../src/models/organizations.js');
vi.unmock('../../../src/models/organizationMemberships.js');
vi.unmock('../../../src/models/webauthnChallenges.js');

// The predicate the loader filters on. It used to ask whether a file ended with its own
// extension, which is always true, so everything but index was imported and required to
// default export a model initialiser.
describe('isModelFile', () => {
  it.each(['users.ts', 'users.js', 'organizationMemberships.js'])('loads %s', async (file) => {
    const { isModelFile } = await import('../../../src/models');

    expect(isModelFile(file)).toBe(true);
  });

  it.each(['index.ts', 'index.js', 'users.js.map', 'users.d.ts', 'notes.txt', 'README.md'])(
    'skips %s',
    async (file) => {
      const { isModelFile } = await import('../../../src/models');

      expect(isModelFile(file)).toBe(false);
    },
  );
});

describe('models initialization', () => {
  beforeEach(() => {
    vi.resetModules(); // ensure fresh import
  });

  it('loads all models successfully', async () => {
    const { initializeModels } = await import('../../../src/models');

    const models = await initializeModels();

    expect(models).toBeDefined();
    expect(models.sequelize).toBeDefined();

    // sanity checks for key models
    expect(models.User).toBeDefined();
    expect(models.Session).toBeDefined();
    expect(models.AuthEvent).toBeDefined();
    expect(models.WebAuthnChallenge).toBeDefined();
  });

  it('models expose attributes', async () => {
    const { initializeModels } = await import('../../../src/models');

    const models = await initializeModels();

    const userAttrs = models.User.getAttributes();
    const sessionAttrs = models.Session.getAttributes();

    expect(userAttrs).toBeDefined();
    expect(Object.keys(userAttrs).length).toBeGreaterThan(0);

    expect(sessionAttrs).toBeDefined();
    expect(Object.keys(sessionAttrs).length).toBeGreaterThan(0);
  });

  it('associations do not throw during initialization', async () => {
    const { initializeModels } = await import('../../../src/models');

    const models = await initializeModels();

    // if associations were broken, initializeModels would throw
    expect(models).toBeTruthy();
  });
});
