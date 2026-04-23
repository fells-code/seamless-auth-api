/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions
      ADD COLUMN IF NOT EXISTS "refreshTokenLookup" character varying(64);

      CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_lookup
      ON public.sessions USING btree ("refreshTokenLookup");
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS idx_sessions_refresh_token_lookup;

      ALTER TABLE public.sessions
      DROP COLUMN IF EXISTS "refreshTokenLookup";
    `);
  },
};
