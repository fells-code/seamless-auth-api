/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * The hash of the code a magic link carries in its fragment (#594). A link without one
 * was issued before the code existed and can no longer be confirmed.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.magic_link_tokens ADD COLUMN IF NOT EXISTS code_hash TEXT;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.magic_link_tokens DROP COLUMN IF EXISTS code_hash;
    `);
  },
};
