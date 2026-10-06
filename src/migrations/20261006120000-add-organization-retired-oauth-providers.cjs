/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * OAuth provider ids the organization's members may no longer sign in with. Used to
 * retire a legacy identity provider one organization at a time during a migration
 * cutover, and to bring it back for a rollback.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('organizations', 'retired_oauth_providers', {
      type: Sequelize.JSONB,
      allowNull: false,
      defaultValue: [],
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('organizations', 'retired_oauth_providers');
  },
};
