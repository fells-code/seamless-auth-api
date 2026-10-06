/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * When the refresh rotation chain a session belongs to began, copied forward on every
 * rotation so the absolute session lifetime is measured from sign-in rather than from
 * the latest refresh.
 *
 * Existing rows are backfilled from their own creation time, which is the start of the
 * rotation that made them. Chains already in flight are therefore capped from their
 * most recent refresh, not from the sign-in that started them.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions
      ADD COLUMN IF NOT EXISTS "chainStartedAt" timestamp with time zone;

      UPDATE public.sessions
      SET "chainStartedAt" = "createdAt"
      WHERE "chainStartedAt" IS NULL;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions
      DROP COLUMN IF EXISTS "chainStartedAt";
    `);
  },
};
