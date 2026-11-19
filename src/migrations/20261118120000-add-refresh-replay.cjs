/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * The refresh replay window (#598): when a session rotated, its successor's refresh token
 * sealed for a holder of the rotated token, and how many times it has been replayed.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions ADD COLUMN IF NOT EXISTS "rotatedAt" timestamp with time zone;
      ALTER TABLE public.sessions ADD COLUMN IF NOT EXISTS "replayTokenCiphertext" text;
      ALTER TABLE public.sessions
        ADD COLUMN IF NOT EXISTS "replayCount" integer NOT NULL DEFAULT 0;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions DROP COLUMN IF EXISTS "replayCount";
      ALTER TABLE public.sessions DROP COLUMN IF EXISTS "replayTokenCiphertext";
      ALTER TABLE public.sessions DROP COLUMN IF EXISTS "rotatedAt";
    `);
  },
};
