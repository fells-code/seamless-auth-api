/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Signed, retried webhooks (ADR 0005). Deliveries are made from committed audit rows, read past
 * a cursor in `event_dispatch_cursors`, so an event is sent only once its row exists and none is
 * lost between happening and being queued. A delivery's id is its `webhook-id`, and it stays the
 * same across retries and redelivery. `(endpointId, authEventSeq)` is unique so that a dispatch
 * repeated after a crash cannot queue the same event twice.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.webhook_endpoints (
        id uuid NOT NULL,
        url character varying(2048) NOT NULL,
        description text,
        "eventTypes" character varying(64)[] NOT NULL,
        enabled boolean NOT NULL DEFAULT true,
        "disabledReason" character varying(20),
        version integer NOT NULL DEFAULT 1,
        "secretCiphertext" text NOT NULL,
        "secretIv" text NOT NULL,
        "secretTag" text NOT NULL,
        "previousSecretCiphertext" text,
        "previousSecretIv" text,
        "previousSecretTag" text,
        "previousSecretExpiresAt" timestamp with time zone,
        "failingSince" timestamp with time zone,
        "createdBy" uuid,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT webhook_endpoints_pkey PRIMARY KEY (id),
        CONSTRAINT webhook_endpoints_disabled_reason
          CHECK ("disabledReason" IS NULL OR "disabledReason" IN ('gone', 'failing', 'manual'))
      );

      CREATE TABLE IF NOT EXISTS public.webhook_deliveries (
        id uuid NOT NULL,
        "endpointId" uuid NOT NULL,
        "eventType" character varying(64) NOT NULL,
        "authEventSeq" bigint,
        payload text NOT NULL,
        status character varying(20) NOT NULL,
        attempts integer NOT NULL DEFAULT 0,
        "nextAttemptAt" timestamp with time zone,
        "lastAttemptAt" timestamp with time zone,
        "lastStatusCode" integer,
        "lastFailure" character varying(32),
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id),
        CONSTRAINT webhook_deliveries_endpoint_fkey
          FOREIGN KEY ("endpointId") REFERENCES public.webhook_endpoints(id) ON DELETE CASCADE,
        CONSTRAINT webhook_deliveries_status
          CHECK (status IN ('pending', 'succeeded', 'failed', 'dead')),
        CONSTRAINT webhook_deliveries_event_once UNIQUE ("endpointId", "authEventSeq")
      );

      CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
        ON public.webhook_deliveries ("nextAttemptAt")
        WHERE status IN ('pending', 'failed');

      CREATE INDEX IF NOT EXISTS webhook_deliveries_endpoint_created_idx
        ON public.webhook_deliveries ("endpointId", "createdAt" DESC);

      CREATE INDEX IF NOT EXISTS webhook_deliveries_created_idx
        ON public.webhook_deliveries ("createdAt");

      CREATE TABLE IF NOT EXISTS public.event_dispatch_cursors (
        name character varying(100) NOT NULL,
        "lastSeq" bigint NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT event_dispatch_cursors_pkey PRIMARY KEY (name)
      );
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP TABLE IF EXISTS public.webhook_deliveries;
      DROP TABLE IF EXISTS public.webhook_endpoints;
      DROP TABLE IF EXISTS public.event_dispatch_cursors;
    `);
  },
};
