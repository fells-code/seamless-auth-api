'use strict';

/**
 * Records whether a credential's attestation carried a certificate chain.
 *
 * `attestation_format` alone cannot say. The 'packed' format covers both a
 * statement signed by a manufacturer's attestation key and one the credential
 * signed for itself, and only the first can be traced anywhere. An audit reading
 * the format sees 'packed' for both.
 *
 * Values are 'none', 'self' and 'basic'.
 *
 * Nullable with no backfill: it was not captured for existing credentials and
 * cannot be recovered from what was stored.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('credentials', 'attestationType', {
      type: Sequelize.STRING,
      allowNull: true,
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('credentials', 'attestationType');
  },
};
