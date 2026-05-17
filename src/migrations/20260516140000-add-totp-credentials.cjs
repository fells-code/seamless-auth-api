/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.totp_credentials (
        id uuid NOT NULL,
        "userId" uuid NOT NULL,
        "secretCiphertext" text NOT NULL,
        "secretIv" character varying(255) NOT NULL,
        "secretTag" character varying(255) NOT NULL,
        issuer character varying(255) NOT NULL,
        "accountName" character varying(255) NOT NULL,
        enabled boolean DEFAULT false NOT NULL,
        "verifiedAt" timestamp with time zone,
        "lastUsedAt" timestamp with time zone,
        "lastUsedCounter" bigint,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL
      );

      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'totp_credentials_pkey'
        ) THEN
          ALTER TABLE ONLY public.totp_credentials
          ADD CONSTRAINT totp_credentials_pkey PRIMARY KEY (id);
        END IF;
      END $$;

      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'totp_credentials_userId_fkey'
        ) THEN
          ALTER TABLE ONLY public.totp_credentials
          ADD CONSTRAINT "totp_credentials_userId_fkey"
          FOREIGN KEY ("userId") REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;
        END IF;
      END $$;

      CREATE INDEX IF NOT EXISTS idx_totp_credentials_user_id
      ON public.totp_credentials USING btree ("userId");

      CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_credentials_one_enabled_per_user
      ON public.totp_credentials USING btree ("userId")
      WHERE enabled = true;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP TABLE IF EXISTS public.totp_credentials;
    `);
  },
};
