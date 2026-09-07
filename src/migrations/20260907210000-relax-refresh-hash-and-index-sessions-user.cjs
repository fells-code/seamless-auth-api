/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      -- refreshTokenHash is no longer written. A refresh token is 32 random bytes, so
      -- the keyed fingerprint in refreshTokenLookup is what authenticates it and bcrypt
      -- added cost without resistance. Made nullable rather than dropped so a rolling
      -- deploy where older instances still write the column keeps working; a later
      -- release removes it.
      ALTER TABLE public.sessions
      ALTER COLUMN "refreshTokenHash" DROP NOT NULL;

      -- Every other table queried by user has this index. sessions did not, and it is
      -- read by userId on every sign-in (the concurrent session limit), on every session
      -- list and logout-all, and by four admin handlers, against a table that gains a
      -- row on each token rotation and is never pruned.
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id
      ON public.sessions USING btree ("userId");
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS idx_sessions_user_id;

      -- Only restorable when no row has been written without one.
      UPDATE public.sessions SET "refreshTokenHash" = '' WHERE "refreshTokenHash" IS NULL;

      ALTER TABLE public.sessions
      ALTER COLUMN "refreshTokenHash" SET NOT NULL;
    `);
  },
};
