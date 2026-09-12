'use strict';

/**
 * The dimensions the auth path is measured along, on every audit row.
 *
 * None of them can be backfilled: the mail provider is taken from an address the
 * row deliberately does not store, the device class from a user agent that is only
 * meaningful once the adapter forwards the browser's, and the attempt id from a
 * token claim that did not exist. Each is recorded at write time for that reason.
 *
 * `user_agent` widens to text at the same time. It was `varchar(255)`, which was
 * never hit while the adapter wrote its own short user agent, and would have failed
 * the whole audit write for a long browser one.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.changeColumn('auth_events', 'user_agent', {
      type: Sequelize.TEXT,
      allowNull: true,
    });

    // Which deployment wrote the row, so rows exported across a fleet stay
    // attributable. The same value as `sessions."infraId"`.
    await queryInterface.addColumn('auth_events', 'deployment_id', {
      type: Sequelize.STRING,
      allowNull: true,
    });

    await queryInterface.addColumn('auth_events', 'device_class', {
      type: Sequelize.STRING(32),
      allowNull: true,
    });

    await queryInterface.addColumn('auth_events', 'mail_provider', {
      type: Sequelize.STRING(32),
      allowNull: true,
    });

    // Null when the subject is unknown, so it is distinguishable from a known
    // non-owner.
    await queryInterface.addColumn('auth_events', 'owner', {
      type: Sequelize.BOOLEAN,
      allowNull: true,
    });

    await queryInterface.addColumn('auth_events', 'attempt_id', {
      type: Sequelize.UUID,
      allowNull: true,
    });

    // Partial: most rows are written from an access session and carry no attempt.
    await queryInterface.addIndex('auth_events', ['attempt_id'], {
      name: 'auth_events_attempt_id_idx',
      where: { attempt_id: { [Sequelize.Op.ne]: null } },
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.removeIndex('auth_events', 'auth_events_attempt_id_idx');
    await queryInterface.removeColumn('auth_events', 'attempt_id');
    await queryInterface.removeColumn('auth_events', 'owner');
    await queryInterface.removeColumn('auth_events', 'mail_provider');
    await queryInterface.removeColumn('auth_events', 'device_class');
    await queryInterface.removeColumn('auth_events', 'deployment_id');

    // Only restorable when no stored user agent is longer than the old limit.
    await queryInterface.changeColumn('auth_events', 'user_agent', {
      type: Sequelize.STRING,
      allowNull: true,
    });
  },
};
