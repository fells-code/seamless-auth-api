/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Where an imported user came from: the source system's name and its id for them.
 *
 * Unique on (source, external_id) so re-running an import matches the same person
 * even after their email changed in the source. Unique on (user_id, source) so one
 * account carries at most one id per source, which is what makes a conflicting
 * re-import detectable rather than silently linking a second person.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('user_external_ids', {
      id: {
        type: Sequelize.UUID,
        primaryKey: true,
        allowNull: false,
        defaultValue: Sequelize.literal('gen_random_uuid()'),
      },
      user_id: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: 'users',
          key: 'id',
        },
        onDelete: 'CASCADE',
      },
      source: {
        type: Sequelize.STRING(64),
        allowNull: false,
      },
      external_id: {
        type: Sequelize.STRING(255),
        allowNull: false,
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

    await queryInterface.addIndex('user_external_ids', ['source', 'external_id'], {
      unique: true,
      name: 'idx_user_external_ids_source_external_id_unique',
    });
    await queryInterface.addIndex('user_external_ids', ['user_id', 'source'], {
      unique: true,
      name: 'idx_user_external_ids_user_source_unique',
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('user_external_ids');
  },
};
