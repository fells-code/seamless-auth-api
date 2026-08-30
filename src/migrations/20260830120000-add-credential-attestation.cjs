'use strict';

/**
 * Records how a credential identified itself at registration.
 *
 * `attestation_format` is the statement format the authenticator returned, or
 * 'none' when this deployment did not ask for one. `attestation_verified`
 * records whether that statement was checked against the FIDO Metadata Service.
 *
 * Both nullable with no backfill: neither was captured for existing credentials
 * and neither can be recovered afterwards.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('credentials', 'attestationFormat', {
      type: Sequelize.STRING,
      allowNull: true,
    });

    await queryInterface.addColumn('credentials', 'attestationVerified', {
      type: Sequelize.BOOLEAN,
      allowNull: true,
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('credentials', 'attestationVerified');
    await queryInterface.removeColumn('credentials', 'attestationFormat');
  },
};
