/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * A native client can exchange a provider sign-in for a first-party session of its own,
 * linked to the sign-in's session as its parent (ADR 0003). The link cascades on delete: a
 * child whose parent row is gone must end, and clearing the link would turn it into an
 * ordinary session with nothing bounding it.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.oidc_clients
      ADD COLUMN IF NOT EXISTS "sessionExchangeEnabled" boolean DEFAULT false NOT NULL;

      ALTER TABLE public.sessions
      ADD COLUMN IF NOT EXISTS "parentSessionId" uuid
        REFERENCES public.sessions(id) ON UPDATE CASCADE ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS "exchangeClientId" character varying(255),
      ADD COLUMN IF NOT EXISTS "exchangeGrantType" character varying(255);

      CREATE INDEX IF NOT EXISTS sessions_parent_session_idx
        ON public.sessions ("parentSessionId") WHERE "parentSessionId" IS NOT NULL;

      CREATE INDEX IF NOT EXISTS sessions_exchange_client_idx
        ON public.sessions ("exchangeClientId") WHERE "exchangeClientId" IS NOT NULL;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP INDEX IF EXISTS public.sessions_exchange_client_idx;
      DROP INDEX IF EXISTS public.sessions_parent_session_idx;

      ALTER TABLE public.sessions
      DROP COLUMN IF EXISTS "exchangeGrantType",
      DROP COLUMN IF EXISTS "exchangeClientId",
      DROP COLUMN IF EXISTS "parentSessionId";

      ALTER TABLE public.oidc_clients DROP COLUMN IF EXISTS "sessionExchangeEnabled";
    `);
  },
};
