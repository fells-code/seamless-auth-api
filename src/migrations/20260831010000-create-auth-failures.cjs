'use strict';

/**
 * A dedicated store for the failed authentication attempts that drive account
 * lockout.
 *
 * The count used to be derived from `auth_events`, whose writes swallow every
 * error, so any condition that degraded audit writes stopped failures being
 * counted and silently disabled lockout on every account while authentication
 * carried on. The control and its telemetry were the same data path, failing
 * open at both ends.
 *
 * This table exists so losing the audit trail does not lose the control. It is
 * written separately from the audit event and carries only what the lockout
 * decision needs.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('auth_failures', {
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
      type: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      occurred_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
      },
    });

    // The only query this table serves: failures for one user inside a window.
    await queryInterface.addIndex('auth_failures', ['user_id', 'occurred_at'], {
      name: 'auth_failures_user_id_occurred_at_idx',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeIndex('auth_failures', 'auth_failures_user_id_occurred_at_idx');
    await queryInterface.dropTable('auth_failures');
  },
};
