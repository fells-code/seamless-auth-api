/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Ties each passkey sign-in challenge to the sign-in attempt that asked for it, so
 * starting another attempt for the same account no longer replaces it.
 *
 * Challenges created before this migration have no attempt and cannot be finished; they
 * live for five minutes, so only ceremonies in flight during the upgrade are lost.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.webauthn_challenges
      ADD COLUMN IF NOT EXISTS attempt_id TEXT;

      CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_attempt
      ON public.webauthn_challenges(user_id, purpose, attempt_id);
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS public.idx_webauthn_challenges_attempt;

      ALTER TABLE public.webauthn_challenges
      DROP COLUMN IF EXISTS attempt_id;
    `);
  },
};
