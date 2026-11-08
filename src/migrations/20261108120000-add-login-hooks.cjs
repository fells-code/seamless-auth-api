/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Login hooks (ADR 0005, E5): one HTTPS callout per trigger, signed like a webhook. The claims a
 * `pre_token` hook adds are kept on the session and copied on rotation, so a refresh never calls
 * a hook. Invocations are kept for 30 days.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.login_hooks (
        trigger character varying(20) NOT NULL,
        url character varying(2048) NOT NULL,
        "timeoutMs" integer NOT NULL DEFAULT 2000,
        "failureMode" character varying(10) NOT NULL DEFAULT 'closed',
        enabled boolean NOT NULL DEFAULT true,
        "secretCiphertext" text NOT NULL,
        "secretIv" text NOT NULL,
        "secretTag" text NOT NULL,
        "previousSecretCiphertext" text,
        "previousSecretIv" text,
        "previousSecretTag" text,
        "previousSecretExpiresAt" timestamp with time zone,
        "createdBy" uuid,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT login_hooks_pkey PRIMARY KEY (trigger),
        CONSTRAINT login_hooks_trigger CHECK (trigger IN ('post_login', 'pre_token')),
        CONSTRAINT login_hooks_failure_mode CHECK ("failureMode" IN ('open', 'closed')),
        CONSTRAINT login_hooks_timeout CHECK ("timeoutMs" BETWEEN 100 AND 5000)
      );

      CREATE TABLE IF NOT EXISTS public.login_hook_invocations (
        id uuid NOT NULL,
        trigger character varying(20) NOT NULL,
        "userId" uuid,
        outcome character varying(20) NOT NULL,
        failure character varying(32),
        "statusCode" integer,
        "durationMs" integer NOT NULL,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT login_hook_invocations_pkey PRIMARY KEY (id),
        CONSTRAINT login_hook_invocations_outcome
          CHECK (outcome IN ('allowed', 'denied', 'failed_open', 'failed_closed'))
      );

      CREATE INDEX IF NOT EXISTS login_hook_invocations_trigger_created_idx
        ON public.login_hook_invocations (trigger, "createdAt" DESC);

      CREATE INDEX IF NOT EXISTS login_hook_invocations_created_idx
        ON public.login_hook_invocations ("createdAt");

      ALTER TABLE public.sessions ADD COLUMN IF NOT EXISTS "hookClaims" jsonb;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      ALTER TABLE public.sessions DROP COLUMN IF EXISTS "hookClaims";
      DROP TABLE IF EXISTS public.login_hook_invocations;
      DROP TABLE IF EXISTS public.login_hooks;
    `);
  },
};
