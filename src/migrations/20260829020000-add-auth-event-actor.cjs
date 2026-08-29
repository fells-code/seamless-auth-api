'use strict';

/**
 * Records who performed an audited action, separately from who it happened to.
 *
 * Nullable with no backfill: the actor for existing rows is genuinely unknown,
 * and inventing one would be worse than leaving it empty.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('auth_events', 'actor_user_id', {
      type: Sequelize.UUID,
      allowNull: true,
    });

    await queryInterface.addIndex('auth_events', ['actor_user_id'], {
      name: 'auth_events_actor_user_id_idx',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeIndex('auth_events', 'auth_events_actor_user_id_idx');
    await queryInterface.removeColumn('auth_events', 'actor_user_id');
  },
};
