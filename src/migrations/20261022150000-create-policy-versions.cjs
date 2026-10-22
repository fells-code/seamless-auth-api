'use strict';

/**
 * Versioned auth policy, and the one draft that can be staged against it.
 *
 * `policy_versions` keeps every policy that has ever been applied, so a change can be
 * undone by publishing an older one again. Versions are numbered by the service under an
 * advisory lock rather than by a sequence, because a sequence leaves gaps on rollback and
 * the number is what an operator quotes when asking for a restore.
 *
 * `policy_drafts` holds at most one row. The check on `id` is what makes "the draft" a
 * single thing two administrators edit, instead of one draft each that publish in turn
 * and undo each other.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('policy_versions', {
      version: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        allowNull: false,
      },
      policy: {
        type: Sequelize.JSONB,
        allowNull: false,
      },
      source: {
        type: Sequelize.STRING(16),
        allowNull: false,
      },
      rolled_back_to: {
        type: Sequelize.INTEGER,
        allowNull: true,
        references: { model: 'policy_versions', key: 'version' },
        onDelete: 'RESTRICT',
      },
      created_by: {
        type: Sequelize.UUID,
        allowNull: true,
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.fn('NOW'),
      },
    });

    await queryInterface.addConstraint('policy_versions', {
      type: 'check',
      fields: ['source'],
      name: 'policy_versions_source_check',
      where: { source: ['publish', 'rollback', 'config_patch', 'bootstrap'] },
    });

    await queryInterface.addConstraint('policy_versions', {
      type: 'check',
      fields: ['version'],
      name: 'policy_versions_version_positive',
      where: { version: { [Sequelize.Op.gt]: 0 } },
    });

    await queryInterface.createTable('policy_drafts', {
      id: {
        type: Sequelize.SMALLINT,
        primaryKey: true,
        allowNull: false,
        defaultValue: 1,
      },
      policy: {
        type: Sequelize.JSONB,
        allowNull: false,
      },
      based_on_version: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: { model: 'policy_versions', key: 'version' },
        onDelete: 'RESTRICT',
      },
      created_by: {
        type: Sequelize.UUID,
        allowNull: true,
      },
      updated_by: {
        type: Sequelize.UUID,
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

    await queryInterface.addConstraint('policy_drafts', {
      type: 'check',
      fields: ['id'],
      name: 'policy_drafts_single_row',
      where: { id: 1 },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('policy_drafts');
    await queryInterface.dropTable('policy_versions');
  },
};
