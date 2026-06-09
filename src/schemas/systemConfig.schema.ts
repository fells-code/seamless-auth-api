/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { z } from 'zod';

import { RoleNameSchema } from './roles.schema.js';

export const LoginMethodSchema = z.enum([
  'passkey',
  'magic_link',
  'email_otp',
  'phone_otp',
  'oauth',
]);

export const OAuthProviderConfigSchema = z.object({
  id: z.string().regex(/^[a-z0-9-]{2,40}$/),
  name: z.string().trim().min(1).max(80),
  enabled: z.boolean().default(true),
  clientId: z.string().trim().min(1),
  clientSecretEnv: z.string().trim().min(1),
  authorizationUrl: z.url(),
  tokenUrl: z.url(),
  userInfoUrl: z.url(),
  scopes: z.array(z.string().trim().min(1)).default([]),
  redirectUri: z.url().optional(),
  redirectUris: z.array(z.url()).default([]),
  subjectJsonPath: z.string().trim().min(1).default('sub'),
  emailJsonPath: z.string().trim().min(1).default('email'),
  emailVerifiedJsonPath: z.string().trim().min(1).default('email_verified'),
  nameJsonPath: z.string().trim().min(1).optional(),
  allowSignup: z.boolean().default(true),
  accountLinking: z.enum(['email', 'disabled']).default('email'),
  requireEmailVerified: z.boolean().default(false),
  pkce: z.boolean().optional(),
});

export const LockoutPolicySchema = z.object({
  enabled: z.boolean().default(true),
  maxFailures: z.number().int().positive().default(10),
  windowSeconds: z
    .number()
    .int()
    .positive()
    .default(15 * 60),
  lockoutSeconds: z
    .number()
    .int()
    .positive()
    .default(15 * 60),
});

export const DefaultLockoutPolicy = {
  enabled: true,
  maxFailures: 10,
  windowSeconds: 15 * 60,
  lockoutSeconds: 15 * 60,
} as const;

export const SystemConfigSchema = z.object({
  app_name: z.string().min(3),
  default_roles: z.array(RoleNameSchema).min(1),
  available_roles: z.array(RoleNameSchema).min(1),
  login_methods: z.array(LoginMethodSchema).min(1),
  passkey_login_fallback_enabled: z.boolean(),
  oauth_providers: z.array(OAuthProviderConfigSchema).default([]),
  lockout_policy: LockoutPolicySchema.default(DefaultLockoutPolicy),

  access_token_ttl: z.string().regex(/^\d+[smhd]$/),
  refresh_token_ttl: z.string().regex(/^\d+[smhd]$/),

  rate_limit: z.number().int().positive(),
  delay_after: z.number().int().nonnegative(),

  rpid: z.string().min(1),
  origins: z.array(z.url()).min(1),
});

export type SystemConfig = z.infer<typeof SystemConfigSchema>;
export type OAuthProviderConfig = z.infer<typeof OAuthProviderConfigSchema>;
export type LockoutPolicy = z.infer<typeof LockoutPolicySchema>;
