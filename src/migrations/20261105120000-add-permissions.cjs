/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * Permissions and the roles that grant them (ADR 0004). A mapping names its role rather than
 * referencing a row, because instance roles live in `available_roles`. It references the
 * permission by name so that minting a token reads one table, and it restricts deletion so
 * that removing a permission some role still grants is a refusal rather than a silent loss
 * of access.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.permissions (
        id uuid NOT NULL,
        name character varying(80) NOT NULL,
        description text,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT permissions_pkey PRIMARY KEY (id),
        CONSTRAINT permissions_name_key UNIQUE (name)
      );

      CREATE TABLE IF NOT EXISTS public.role_permissions (
        "roleKind" character varying(20) NOT NULL,
        "roleName" character varying(80) NOT NULL,
        "permissionName" character varying(80) NOT NULL,
        "createdBy" uuid,
        "createdAt" timestamp with time zone NOT NULL,
        CONSTRAINT role_permissions_pkey PRIMARY KEY ("roleKind", "roleName", "permissionName"),
        CONSTRAINT role_permissions_permission_fkey
          FOREIGN KEY ("permissionName") REFERENCES public.permissions(name)
          ON UPDATE RESTRICT ON DELETE RESTRICT,
        CONSTRAINT role_permissions_role_kind CHECK ("roleKind" IN ('instance', 'organization'))
      );

      CREATE INDEX IF NOT EXISTS role_permissions_permission_idx
        ON public.role_permissions ("permissionName");
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DROP TABLE IF EXISTS public.role_permissions;
      DROP TABLE IF EXISTS public.permissions;
    `);
  },
};
