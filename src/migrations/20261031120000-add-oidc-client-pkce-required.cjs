/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * PKCE and the nonce stay required for every existing client. Only a confidential client
 * may opt out of PKCE, and only then of the nonce (ADR 0001, D1).
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.oidc_clients
      ADD COLUMN IF NOT EXISTS "pkceRequired" boolean DEFAULT true NOT NULL,
      ADD COLUMN IF NOT EXISTS "nonceRequired" boolean DEFAULT true NOT NULL;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.oidc_clients DROP COLUMN IF EXISTS "pkceRequired",
      DROP COLUMN IF EXISTS "nonceRequired";
    `);
  },
};
