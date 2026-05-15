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
      ADD COLUMN IF NOT EXISTS "stepUpVerifiedAt" timestamp with time zone,
      ADD COLUMN IF NOT EXISTS "stepUpMethod" character varying(255);

      CREATE INDEX IF NOT EXISTS idx_sessions_step_up_verified_at
      ON public.sessions USING btree ("stepUpVerifiedAt");
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS idx_sessions_step_up_verified_at;

      ALTER TABLE public.sessions
      DROP COLUMN IF EXISTS "stepUpMethod",
      DROP COLUMN IF EXISTS "stepUpVerifiedAt";
    `);
  },
};
