'use strict';

module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      INSERT INTO public.system_config (key, value, "updatedBy", "createdAt", "updatedAt")
      VALUES
        ('login_methods', '["passkey","magic_link"]'::jsonb, NULL, NOW(), NOW()),
        ('passkey_login_fallback_enabled', 'true'::jsonb, NULL, NOW(), NOW())
      ON CONFLICT (key) DO NOTHING;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DELETE FROM public.system_config
      WHERE key IN ('login_methods', 'passkey_login_fallback_enabled');
    `);
  },
};
