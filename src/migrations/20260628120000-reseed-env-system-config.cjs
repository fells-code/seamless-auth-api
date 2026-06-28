'use strict';

// Re-apply env-mapped values over migration-seeded defaults so env vars like
// LOGIN_METHODS take effect on existing installs. Only touches rows never changed
// through the admin API (updatedBy IS NULL); bootstrapSystemConfig keeps them in
// sync on every boot going forward.
module.exports = {
  async up(queryInterface) {
    const loginMethods = process.env.LOGIN_METHODS;
    if (loginMethods) {
      const arr = loginMethods
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      await queryInterface.sequelize.query(
        `UPDATE system_config SET value = CAST(:val AS jsonb), "updatedAt" = NOW()
         WHERE key = 'login_methods' AND "updatedBy" IS NULL`,
        { replacements: { val: JSON.stringify(arr) } },
      );
    }

    const fallback = process.env.PASSKEY_LOGIN_FALLBACK_ENABLED;
    if (fallback) {
      const val = fallback.trim().toLowerCase() === 'true';
      await queryInterface.sequelize.query(
        `UPDATE system_config SET value = CAST(:val AS jsonb), "updatedAt" = NOW()
         WHERE key = 'passkey_login_fallback_enabled' AND "updatedBy" IS NULL`,
        { replacements: { val: JSON.stringify(val) } },
      );
    }
  },

  async down() {
    // No-op: re-seeding from env has no meaningful inverse.
  },
};
