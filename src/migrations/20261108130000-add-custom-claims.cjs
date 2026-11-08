/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Static custom claims (ADR 0005, E6): one set per source. Instance and organization role sets
 * reach first-party access tokens; OpenID Provider client sets are stored here and applied by
 * the provider.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.custom_claims (
        "sourceKind" character varying(32) NOT NULL,
        "sourceName" character varying(200) NOT NULL,
        claims jsonb NOT NULL DEFAULT '{}'::jsonb,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT custom_claims_pkey PRIMARY KEY ("sourceKind", "sourceName"),
        CONSTRAINT custom_claims_source_kind
          CHECK ("sourceKind" IN ('instance_role', 'organization_role', 'oidc_client'))
      );
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`DROP TABLE IF EXISTS public.custom_claims;`);
  },
};
