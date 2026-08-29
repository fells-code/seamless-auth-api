'use strict';

/**
 * Moves WebAuthn challenges off the single `users.challenge` column.
 *
 * That column was shared by registration, login and step-up, so two flows for
 * one user clobbered each other, and it had no expiry: a challenge stayed valid
 * until some later flow happened to overwrite it.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('webauthn_challenges', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
        primaryKey: true,
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: { model: 'users', key: 'id' },
        onDelete: 'CASCADE',
      },
      purpose: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      challenge: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      // Flow state that used to live in users.challengeContext, for example
      // whether the registration asked for PRF.
      context: {
        type: Sequelize.JSONB,
        allowNull: true,
      },
      expires_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      consumed_at: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.fn('NOW'),
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.fn('NOW'),
      },
    });

    // Every lookup is "the live challenge for this user and this flow".
    await queryInterface.addIndex('webauthn_challenges', ['user_id', 'purpose'], {
      name: 'webauthn_challenges_user_purpose_idx',
    });

    // Supports reaping expired rows without scanning the table.
    await queryInterface.addIndex('webauthn_challenges', ['expires_at'], {
      name: 'webauthn_challenges_expires_at_idx',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('webauthn_challenges');
  },
};
