'use strict';

// 0.8.0 seeded authenticator_policy with syncedPasskeys 'block', which refuses every
// iCloud Keychain and Google Password Manager passkey. bootstrapSystemConfig only
// applies a default when the row is absent, so an install that never named the field
// would keep refusing them forever. Only touches rows never changed through the admin
// API (updatedBy IS NULL); an operator who set 'block' through AUTHENTICATOR_POLICY has
// it re-applied from env on the next boot.
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(
      `UPDATE system_config
       SET value = jsonb_set(value, '{syncedPasskeys}', '"allow"'), "updatedAt" = NOW()
       WHERE key = 'authenticator_policy'
         AND "updatedBy" IS NULL
         AND jsonb_typeof(value) = 'object'
         AND value->>'syncedPasskeys' IS DISTINCT FROM 'allow'`,
    );
  },

  async down() {
    // No-op: restoring 'block' would impose it on installs that never had it.
  },
};
