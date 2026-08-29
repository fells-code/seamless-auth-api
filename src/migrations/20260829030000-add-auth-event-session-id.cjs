'use strict';

/**
 * Correlates an audit event to the session it happened in.
 *
 * Nullable with no backfill: the session for existing rows is unrecoverable,
 * and anything that happened before a session existed is legitimately null.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('auth_events', 'session_id', {
      type: Sequelize.UUID,
      allowNull: true,
    });

    await queryInterface.addIndex('auth_events', ['session_id'], {
      name: 'auth_events_session_id_idx',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeIndex('auth_events', 'auth_events_session_id_idx');
    await queryInterface.removeColumn('auth_events', 'session_id');
  },
};
