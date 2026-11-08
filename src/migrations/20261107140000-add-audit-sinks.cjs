/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Audit sinks stream the audit log to a SIEM (ADR 0005, E7). Each sink keeps its own cursor,
 * the `seq` of the last event its destination accepted, and only moves it on success, so a
 * sink that cannot deliver falls behind rather than dropping events. `settings` never holds a
 * credential: it names env vars instead.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.audit_sinks (
        id uuid NOT NULL,
        name character varying(100) NOT NULL,
        kind character varying(16) NOT NULL,
        enabled boolean NOT NULL DEFAULT true,
        settings jsonb NOT NULL,
        "cursorSeq" bigint NOT NULL,
        "failureCount" integer NOT NULL DEFAULT 0,
        "nextAttemptAt" timestamp with time zone,
        "lastDeliveredAt" timestamp with time zone,
        "lastFailure" character varying(32),
        "lastFailureAt" timestamp with time zone,
        "createdBy" uuid,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT audit_sinks_pkey PRIMARY KEY (id),
        CONSTRAINT audit_sinks_kind CHECK (kind IN ('otlp', 'syslog')),
        CONSTRAINT audit_sinks_cursor CHECK ("cursorSeq" >= 0)
      );
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query('DROP TABLE IF EXISTS public.audit_sinks;');
  },
};
