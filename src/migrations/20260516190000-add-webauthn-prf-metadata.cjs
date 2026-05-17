/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.credentials
      ADD COLUMN IF NOT EXISTS "prfCapable" boolean DEFAULT false NOT NULL;

      ALTER TABLE public.users
      ADD COLUMN IF NOT EXISTS challenge_context jsonb;

      CREATE INDEX IF NOT EXISTS idx_credentials_prf_capable
      ON public.credentials USING btree ("prfCapable");
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS idx_credentials_prf_capable;

      ALTER TABLE public.users
      DROP COLUMN IF EXISTS challenge_context;

      ALTER TABLE public.credentials
      DROP COLUMN IF EXISTS "prfCapable";
    `);
  },
};
