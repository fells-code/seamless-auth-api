/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { OidcApplicationSchema as BaseApplicationSchema } from '@seamless-auth/types';
import { z } from 'zod';

// TODO(seamless-auth-types#148): move these to @seamless-auth/types.

export const OidcApplicationSchema = BaseApplicationSchema.extend({
  noticeActionOrigins: z.array(z.string()),
  /** Clients this one acts for. */
  links: z.array(z.string()),
  /** Clients that act for this one. */
  linkedFrom: z.array(z.string()),
});

export type OidcApplicationView = z.infer<typeof OidcApplicationSchema>;

export const OidcApplicationResponseSchema = z.object({ application: OidcApplicationSchema });

export const OidcApplicationCreatedResponseSchema = OidcApplicationResponseSchema.extend({
  clientSecret: z.string().optional(),
});

export const OidcApplicationListResponseSchema = z.object({
  applications: z.array(OidcApplicationSchema),
});

export const OidcApplicationSecretResponseSchema = z.object({
  application: OidcApplicationSchema,
  clientSecret: z.string(),
});

export const OidcApplicationLinkSchema = z.object({
  /** The confidential client that acts. */
  clientId: z.string(),
  /** The public client it acts for. */
  linkedClientId: z.string(),
  createdBy: z.string().nullable(),
  createdAt: z.string(),
});

export const OidcApplicationLinksResponseSchema = z.object({
  links: z.array(OidcApplicationLinkSchema),
  linkedFrom: z.array(OidcApplicationLinkSchema),
});

export const OidcApplicationLinkResponseSchema = z.object({ link: OidcApplicationLinkSchema });
