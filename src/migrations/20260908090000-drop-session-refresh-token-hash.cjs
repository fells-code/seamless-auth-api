/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
'use strict';

/**
 * Second half of removing the bcrypt hash from sessions.
 *
 * The release before this one stopped writing and reading the column and dropped its
 * NOT NULL. This one removes it. The two are deliberately separate releases: dropping
 * it in the same release that stopped writing it would break every session insert made
 * by an instance still running the previous version during a rolling deploy.
 */
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions
      DROP COLUMN IF EXISTS "refreshTokenHash";
    `);
  },

  async down(queryInterface) {
    // Restored nullable rather than NOT NULL. The values are gone and nothing reads
    // them, so there is nothing to put back and no column state that would accept a
    // backfill of anything meaningful.
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions
      ADD COLUMN IF NOT EXISTS "refreshTokenHash" text;
    `);
  },
};
