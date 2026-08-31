'use strict';

/**
 * Drops the WebAuthn challenge columns that moved to `webauthn_challenges`.
 *
 * `20260829040000-create-webauthn-challenges` gave challenges their own table
 * with a purpose, an expiry and one-time use. It left these two behind so a
 * rollback could not lose challenge state, and nothing has read or written
 * either since.
 *
 * The `down` restores both nullable, which is the shape they had. It does not
 * restore data, and does not need to: a challenge lives 300 seconds
 * (`CHALLENGE_TTL_SECONDS`), so anything a rollback could have carried across is
 * already expired. At worst an in-flight ceremony fails and the user starts it
 * again.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.removeColumn('users', 'challenge');
    await queryInterface.removeColumn('users', 'challenge_context');
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.addColumn('users', 'challenge', {
      type: Sequelize.STRING(255),
      allowNull: true,
    });

    await queryInterface.addColumn('users', 'challenge_context', {
      type: Sequelize.JSONB,
      allowNull: true,
    });
  },
};
