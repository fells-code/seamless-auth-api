'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
CREATE TABLE public.auth_actions (
    id uuid NOT NULL,
    endpoint character varying(255) NOT NULL,
    method character varying(255) NOT NULL,
    count integer DEFAULT 0 NOT NULL,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);

CREATE TABLE public.auth_events (
    id uuid NOT NULL,
    user_id uuid,
    type character varying(255) NOT NULL,
    ip_address character varying(255),
    user_agent character varying(255),
    metadata jsonb,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);

CREATE TABLE public.credentials (
    id character varying(255) NOT NULL,
    "userId" uuid NOT NULL,
    "publicKey" bytea NOT NULL,
    counter integer DEFAULT 0 NOT NULL,
    transports json,
    backedup boolean DEFAULT false NOT NULL,
    "deviceType" character varying(255),
    "friendlyName" character varying(255) DEFAULT NULL::character varying,
    "lastUsedAt" timestamp with time zone,
    platform character varying(255),
    browser character varying(255),
    "deviceInfo" character varying(255),
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);

CREATE TABLE public.sessions (
    id uuid NOT NULL,
    "userId" uuid NOT NULL,
    "infraId" character varying(255),
    mode character varying(255) NOT NULL,
    "refreshTokenHash" text NOT NULL,
    "userAgent" text,
    "ipAddress" character varying(255),
    "deviceName" character varying(255),
    "lastUsedAt" timestamp with time zone NOT NULL,
    "expiresAt" timestamp with time zone NOT NULL,
    "idleExpiresAt" timestamp with time zone NOT NULL,
    "replacedBySessionId" uuid,
    "revokedAt" timestamp with time zone,
    "revokedReason" character varying(255),
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);

CREATE TABLE public.system_config (
    key character varying(255) NOT NULL,
    value jsonb NOT NULL,
    "updatedBy" uuid,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);

CREATE TABLE public.users (
    id uuid NOT NULL,
    email character varying(255) NOT NULL,
    phone character varying(255) NOT NULL,
    roles character varying(255)[] DEFAULT (ARRAY[]::character varying[])::character varying(255)[] NOT NULL,
    email_verification_token character varying(255),
    email_verification_token_expiry bigint,
    phone_verification_token character varying(255),
    phone_verification_token_expiry bigint,
    revoked boolean DEFAULT false NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    phone_verified boolean DEFAULT false NOT NULL,
    challenge character varying(255),
    last_login timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE ONLY public.auth_actions
    ADD CONSTRAINT auth_actions_pkey PRIMARY KEY (id);

    ALTER TABLE ONLY public.auth_events
    ADD CONSTRAINT auth_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_pkey PRIMARY KEY (key);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_phone_key UNIQUE (phone);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX auth_action_unique_usage_key ON public.auth_actions USING btree (endpoint, method);
CREATE UNIQUE INDEX system_config_key ON public.system_config USING btree (key);

ALTER TABLE ONLY public.auth_events
    ADD CONSTRAINT auth_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT "credentials_userId_fkey" FOREIGN KEY ("userId") REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;
`);
  },

  async down() {
    // NO OP
  },
};
