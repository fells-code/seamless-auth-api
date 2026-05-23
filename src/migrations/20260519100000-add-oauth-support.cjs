/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('oauth_identities', {
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
      provider_id: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      provider_subject: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      profile: {
        type: Sequelize.JSONB,
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

    await queryInterface.addIndex('oauth_identities', ['provider_id', 'provider_subject'], {
      unique: true,
      name: 'idx_oauth_identities_provider_subject_unique',
    });
    await queryInterface.addIndex('oauth_identities', ['user_id'], {
      name: 'idx_oauth_identities_user_id',
    });

    await queryInterface.sequelize.query(`
      INSERT INTO system_config (key, value, "updatedBy", "createdAt", "updatedAt")
      VALUES ('oauth_providers', '[]'::jsonb, NULL, NOW(), NOW())
      ON CONFLICT (key) DO NOTHING;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DELETE FROM system_config
      WHERE key = 'oauth_providers';
    `);
    await queryInterface.dropTable('oauth_identities');
  },
};
