/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Single-use recovery codes, stored as keyed hashes, and the flag that marks a session a
 * recovery issued: restricted to enrolling a new factor until one is enrolled.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.recovery_codes (
        id uuid NOT NULL,
        "userId" uuid NOT NULL,
        "codeHash" character varying(64) NOT NULL,
        "usedAt" timestamp with time zone,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT recovery_codes_pkey PRIMARY KEY (id),
        CONSTRAINT "recovery_codes_userId_fkey"
          FOREIGN KEY ("userId") REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_codes_user_hash
      ON public.recovery_codes USING btree ("userId", "codeHash");

      ALTER TABLE public.sessions
      ADD COLUMN IF NOT EXISTS recovery boolean DEFAULT false NOT NULL;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions DROP COLUMN IF EXISTS recovery;
      DROP TABLE IF EXISTS public.recovery_codes;
    `);
  },
};
