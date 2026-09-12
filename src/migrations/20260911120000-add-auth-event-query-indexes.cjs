'use strict';

/**
 * Covers the ways `auth_events` is read that neither existing index helps.
 *
 * `user_id` had no index at all, despite being the foreign key and the filter for
 * the per-user event list. Paired with `created_at` so the list's `ORDER BY
 * created_at DESC ... LIMIT` and the funnel self-join's `created_at >=` probe are
 * both answered by one range scan instead of a scan and a sort.
 *
 * `type` leads the second index because the metrics endpoints and the funnel CTEs
 * all name one type or a short `IN` list before constraining the window, and a
 * `created_at`-first index would have to walk the whole window for every type.
 *
 * `created_at` alone serves the reads that name neither: the unfiltered event list,
 * which is the dashboard's default view, and the deployment-wide summary and
 * timeseries. A composite index cannot be used for a range on its second column.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.addIndex('auth_events', ['user_id', 'created_at'], {
      name: 'auth_events_user_id_created_at_idx',
    });

    await queryInterface.addIndex('auth_events', ['type', 'created_at'], {
      name: 'auth_events_type_created_at_idx',
    });

    await queryInterface.addIndex('auth_events', ['created_at'], {
      name: 'auth_events_created_at_idx',
    });
  },

  async down(queryInterface) {
    await queryInterface.removeIndex('auth_events', 'auth_events_created_at_idx');
    await queryInterface.removeIndex('auth_events', 'auth_events_type_created_at_idx');
    await queryInterface.removeIndex('auth_events', 'auth_events_user_id_created_at_idx');
  },
};
