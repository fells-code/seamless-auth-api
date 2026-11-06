/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

'use strict';

/**
 * The catalogue of organization roles (ADR 0004, P5). Seeded with the built-ins and every
 * value memberships already hold, spelled as they are, so nobody loses a role and no membership
 * is rewritten. A value too long for the column stays held, and is simply not in the catalogue.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface) {
    await queryInterface.sequelize.query(`
      CREATE TABLE IF NOT EXISTS public.organization_roles (
        name character varying(80) NOT NULL,
        description text,
        "builtIn" boolean DEFAULT false NOT NULL,
        "createdAt" timestamp with time zone NOT NULL,
        "updatedAt" timestamp with time zone NOT NULL,
        CONSTRAINT organization_roles_pkey PRIMARY KEY (name)
      );

      INSERT INTO public.organization_roles (name, description, "builtIn", "createdAt", "updatedAt")
      VALUES
        ('owner', 'Full control of the organization, including its owners.', true, now(), now()),
        ('admin', 'Manages the organization and its members.', true, now(), now()),
        ('member', 'Belongs to the organization.', true, now(), now())
      ON CONFLICT (name) DO NOTHING;

      INSERT INTO public.organization_roles (name, "createdAt", "updatedAt")
      SELECT DISTINCT held.role, now(), now()
      FROM public.organization_memberships membership
      CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(membership.roles) = 'array'
          THEN membership.roles ELSE '[]'::jsonb END
      ) AS held(role)
      WHERE length(held.role) BETWEEN 1 AND 80
      ON CONFLICT (name) DO NOTHING;
    `);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`
      DELETE FROM public.role_permissions WHERE "roleKind" = 'organization';
      DROP TABLE IF EXISTS public.organization_roles;
    `);
  },
};
