/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * A link lets a confidential client act for a public client of the same adopter, so a
 * backend can send account notices to users of its desktop app (ADR 0002, N4 and N5).
 * `noticeActionOrigins` gives a client without https redirects somewhere an action link
 * may point.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.oidc_clients
      ADD COLUMN IF NOT EXISTS "noticeActionOrigins" jsonb DEFAULT '[]'::jsonb NOT NULL;

      CREATE TABLE IF NOT EXISTS public.oidc_client_links (
        "clientId" character varying(255) NOT NULL,
        "linkedClientId" character varying(255) NOT NULL,
        "createdBy" uuid,
        "createdAt" timestamp with time zone NOT NULL,
        CONSTRAINT oidc_client_links_pkey PRIMARY KEY ("clientId", "linkedClientId"),
        CONSTRAINT oidc_client_links_client_fkey
          FOREIGN KEY ("clientId") REFERENCES public.oidc_clients(id) ON UPDATE CASCADE ON DELETE CASCADE,
        CONSTRAINT oidc_client_links_linked_client_fkey
          FOREIGN KEY ("linkedClientId") REFERENCES public.oidc_clients(id) ON UPDATE CASCADE ON DELETE CASCADE,
        CONSTRAINT oidc_client_links_distinct CHECK ("clientId" <> "linkedClientId")
      );

      CREATE INDEX IF NOT EXISTS oidc_client_links_linked_client_idx
        ON public.oidc_client_links ("linkedClientId");
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP TABLE IF EXISTS public.oidc_client_links;
      ALTER TABLE public.oidc_clients DROP COLUMN IF EXISTS "noticeActionOrigins";
    `);
  },
};
