/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Provider state for the OpenID Provider service (ADR 0001, D5). `oidc_payloads` holds every
 * `oidc-provider` model as JSONB because the library's payload set changes between versions,
 * and it also holds the inbound OAuth state replay cache (#414), so it is created whether or
 * not the provider is in use. Clients and resources are first-class tables.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.oidc_payloads (
        id character varying(512) NOT NULL,
        model character varying(64) NOT NULL,
        payload jsonb NOT NULL,
        "grantId" character varying(512),
        "userCode" character varying(512),
        uid character varying(512),
        "sessionId" uuid,
        "expiresAt" timestamp with time zone NOT NULL,
        "consumedAt" timestamp with time zone,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT oidc_payloads_pkey PRIMARY KEY (model, id)
      );

      CREATE INDEX IF NOT EXISTS idx_oidc_payloads_grant
      ON public.oidc_payloads USING btree (model, "grantId") WHERE "grantId" IS NOT NULL;

      CREATE INDEX IF NOT EXISTS idx_oidc_payloads_user_code
      ON public.oidc_payloads USING btree (model, "userCode") WHERE "userCode" IS NOT NULL;

      CREATE INDEX IF NOT EXISTS idx_oidc_payloads_uid
      ON public.oidc_payloads USING btree (model, uid) WHERE uid IS NOT NULL;

      CREATE INDEX IF NOT EXISTS idx_oidc_payloads_session
      ON public.oidc_payloads USING btree ("sessionId") WHERE "sessionId" IS NOT NULL;

      CREATE INDEX IF NOT EXISTS idx_oidc_payloads_expires
      ON public.oidc_payloads USING btree ("expiresAt");

      CREATE TABLE IF NOT EXISTS public.oidc_clients (
        id character varying(255) NOT NULL,
        name character varying(255) NOT NULL,
        "firstParty" boolean DEFAULT false NOT NULL,
        "clientType" character varying(16) NOT NULL,
        "tokenEndpointAuthMethod" character varying(32) NOT NULL,
        jwks jsonb,
        "jwksUri" text,
        "secretLookup" character varying(64),
        "redirectUris" jsonb DEFAULT '[]'::jsonb NOT NULL,
        "postLogoutRedirectUris" jsonb DEFAULT '[]'::jsonb NOT NULL,
        "grantTypes" jsonb DEFAULT '["authorization_code","refresh_token"]'::jsonb NOT NULL,
        "backchannelLogoutUri" text,
        "accessTokenTtlSeconds" integer,
        "idTokenTtlSeconds" integer,
        "refreshTokenTtlSeconds" integer,
        "deviceFlowEnabled" boolean DEFAULT false NOT NULL,
        "noticesEnabled" boolean DEFAULT false NOT NULL,
        "disabledAt" timestamp with time zone,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT oidc_clients_pkey PRIMARY KEY (id),
        CONSTRAINT oidc_clients_type_check CHECK ("clientType" IN ('public', 'confidential')),
        CONSTRAINT oidc_clients_auth_method_check CHECK (
          "tokenEndpointAuthMethod" IN
            ('private_key_jwt', 'none', 'client_secret_basic', 'client_secret_post')
        ),
        CONSTRAINT oidc_clients_public_auth_check CHECK (
          ("clientType" = 'public') = ("tokenEndpointAuthMethod" = 'none')
        )
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_clients_secret_lookup
      ON public.oidc_clients USING btree ("secretLookup") WHERE "secretLookup" IS NOT NULL;

      CREATE TABLE IF NOT EXISTS public.oidc_resources (
        id uuid NOT NULL,
        identifier text NOT NULL,
        name character varying(255) NOT NULL,
        scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
        "accessTokenTtlSeconds" integer,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT oidc_resources_pkey PRIMARY KEY (id),
        CONSTRAINT oidc_resources_identifier_key UNIQUE (identifier)
      );

      CREATE TABLE IF NOT EXISTS public.oidc_client_resources (
        id uuid NOT NULL,
        "clientId" character varying(255) NOT NULL,
        "resourceId" uuid NOT NULL,
        scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT oidc_client_resources_pkey PRIMARY KEY (id),
        CONSTRAINT oidc_client_resources_client_fkey
          FOREIGN KEY ("clientId") REFERENCES public.oidc_clients(id) ON UPDATE CASCADE ON DELETE CASCADE,
        CONSTRAINT oidc_client_resources_resource_fkey
          FOREIGN KEY ("resourceId") REFERENCES public.oidc_resources(id) ON UPDATE CASCADE ON DELETE CASCADE,
        CONSTRAINT oidc_client_resources_unique UNIQUE ("clientId", "resourceId")
      );
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP TABLE IF EXISTS public.oidc_client_resources;
      DROP TABLE IF EXISTS public.oidc_resources;
      DROP TABLE IF EXISTS public.oidc_clients;
      DROP TABLE IF EXISTS public.oidc_payloads;
    `);
  },
};
