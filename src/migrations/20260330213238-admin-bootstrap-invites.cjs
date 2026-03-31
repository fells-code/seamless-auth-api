'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('bootstrap_invites', {
      id: {
        type: Sequelize.UUID,
        allowNull: false,
        primaryKey: true,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
      },
      email: {
        type: Sequelize.STRING(320),
        allowNull: false,
      },
      role: {
        type: Sequelize.ENUM('admin'),
        allowNull: false,
        defaultValue: 'admin',
      },
      token_hash: {
        type: Sequelize.STRING(255),
        allowNull: false,
        unique: true,
      },
      expires_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      consumed_at: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      created_by: {
        type: Sequelize.STRING(64),
        allowNull: false,
        defaultValue: 'bootstrap',
      },
      created_ip: {
        type: Sequelize.STRING(64),
        allowNull: true,
      },
      created_user_agent: {
        type: Sequelize.TEXT,
        allowNull: true,
      },
      last_sent_at: {
        type: Sequelize.DATE,
        allowNull: true,
      },
      attempt_count: {
        type: Sequelize.INTEGER,
        allowNull: false,
        defaultValue: 0,
      },
      created_at: {
        allowNull: false,
        type: Sequelize.DATE,
      },
      updated_at: {
        allowNull: false,
        type: Sequelize.DATE,
      },
    });

    await queryInterface.addIndex('bootstrap_invites', ['email']);
    await queryInterface.addIndex('bootstrap_invites', ['expires_at']);
    await queryInterface.addIndex('bootstrap_invites', ['consumed_at']);
  },

  async down(queryInterface) {
    await queryInterface.dropTable('bootstrap_invites');
    await queryInterface.sequelize.query('DROP TYPE IF EXISTS "enum_bootstrap_invites_role";');
  },
};
