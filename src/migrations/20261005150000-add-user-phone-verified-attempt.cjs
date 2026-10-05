/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Which registration attempt verified the phone, while the account's email is not yet
 * proven. The first email verification keeps the phone only when the same attempt
 * verified it, so a phone planted through someone else's attempt does not survive the
 * owner claiming the account. Cleared once the account is verified.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('users', 'phone_verified_attempt_id', {
      type: Sequelize.UUID,
      allowNull: true,
    });
  },

  async down(queryInterface) {
    await queryInterface.removeColumn('users', 'phone_verified_attempt_id');
  },
};
