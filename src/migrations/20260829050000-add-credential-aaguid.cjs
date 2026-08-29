'use strict';

/**
 * Records which authenticator model a credential came from.
 *
 * Nullable with no backfill: the AAGUID was never captured for existing
 * credentials and cannot be recovered from a stored public key, so those read as
 * unknown rather than being guessed at.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('credentials', 'aaguid', {
      type: Sequelize.STRING,
      allowNull: true,
    });

    // Supports "which authenticator models are deployed" and the allow or deny
    // list lookups that policy will need.
    await queryInterface.addIndex('credentials', ['aaguid'], {
      name: 'credentials_aaguid_idx',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeIndex('credentials', 'credentials_aaguid_idx');
    await queryInterface.removeColumn('credentials', 'aaguid');
  },
};
