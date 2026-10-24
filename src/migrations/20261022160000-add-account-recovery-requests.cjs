/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Self-service account recovery: a request proven through a verified email or phone,
 * which completes only after the configured delay and can be cancelled until then.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.account_recovery_requests (
        id uuid NOT NULL,
        "userId" uuid NOT NULL,
        channel character varying(16) NOT NULL,
        state character varying(16) NOT NULL,
        "attemptId" character varying(255),
        "codeAttemptId" character varying(255),
        "codeHash" character varying(255),
        "codeExpiresAt" timestamp with time zone,
        "failedAttempts" integer DEFAULT 0 NOT NULL,
        "cancelTokenHash" character varying(64),
        "requestedAt" timestamp with time zone,
        "completesAt" timestamp with time zone,
        "cancelledAt" timestamp with time zone,
        "completedAt" timestamp with time zone,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT account_recovery_requests_pkey PRIMARY KEY (id),
        CONSTRAINT "account_recovery_requests_userId_fkey"
          FOREIGN KEY ("userId") REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_account_recovery_requests_user
      ON public.account_recovery_requests USING btree ("userId");

      CREATE UNIQUE INDEX IF NOT EXISTS idx_account_recovery_requests_cancel_token
      ON public.account_recovery_requests USING btree ("cancelTokenHash");
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP TABLE IF EXISTS public.account_recovery_requests;
    `);
  },
};
