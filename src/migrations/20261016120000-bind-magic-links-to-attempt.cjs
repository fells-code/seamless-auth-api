/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Ties each magic link to the sign-in attempt that requested it, and records when its
 * session was issued so a confirmed link is redeemed once.
 *
 * Links created before this migration have no attempt and can no longer be collected.
 * They live for fifteen minutes, so only links in flight during the upgrade are lost.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.magic_link_tokens
      ADD COLUMN IF NOT EXISTS attempt_id TEXT,
      ADD COLUMN IF NOT EXISTS redeemed_at TIMESTAMPTZ;

      CREATE INDEX IF NOT EXISTS idx_magic_link_attempt_id
      ON public.magic_link_tokens(attempt_id);
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS public.idx_magic_link_attempt_id;

      ALTER TABLE public.magic_link_tokens
      DROP COLUMN IF EXISTS redeemed_at,
      DROP COLUMN IF EXISTS attempt_id;
    `);
  },
};
