/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * What a session's sign-in and step-ups proved, from which the provider's `acr` and `amr`
 * are derived (ADR 0001, D9). Rows that predate the columns get no methods, so they never
 * carry `acr`, and `authTime` falls back to when the session was created.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions
      ADD COLUMN IF NOT EXISTS "authMethods" jsonb DEFAULT '[]'::jsonb NOT NULL;

      ALTER TABLE public.sessions
      ADD COLUMN IF NOT EXISTS "authTime" timestamp with time zone;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions DROP COLUMN IF EXISTS "authTime";
      ALTER TABLE public.sessions DROP COLUMN IF EXISTS "authMethods";
    `);
  },
};
