/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { getSystemConfig } from '../config/getSystemConfig.js';
import { SYSTEM_CONFIG_DEFAULTS } from '../config/systemConfig.defaults.js';
import { LoginMethodSchema } from '../schemas/systemConfig.schema.js';

export type LoginMethod = 'passkey' | 'magic_link' | 'email_otp' | 'phone_otp' | 'oauth';

export interface LoginPolicy {
  loginMethods: LoginMethod[];
  passkeyFallbackEnabled: boolean;
}

type LoginMethodUser = {
  email?: string | null;
  phone?: string | null;
};

const LOGIN_METHOD_ORDER: LoginMethod[] = [
  'passkey',
  'magic_link',
  'email_otp',
  'phone_otp',
  'oauth',
];

function hasValue(value: string | null | undefined) {
  return typeof value === 'string' && value.trim().length > 0;
}

export function normalizeLoginPolicy(config: Record<string, unknown> | null | undefined) {
  const configuredMethods = Array.isArray(config?.login_methods)
    ? config.login_methods
    : SYSTEM_CONFIG_DEFAULTS.login_methods;
  const validConfiguredMethods = new Set<LoginMethod>();

  for (const method of configuredMethods ?? []) {
    const parsed = LoginMethodSchema.safeParse(method);

    if (parsed.success) {
      validConfiguredMethods.add(parsed.data);
    }
  }

  const loginMethods = LOGIN_METHOD_ORDER.filter((method) => validConfiguredMethods.has(method));

  return {
    loginMethods: loginMethods.length
      ? loginMethods
      : (SYSTEM_CONFIG_DEFAULTS.login_methods as LoginMethod[]),
    passkeyFallbackEnabled:
      typeof config?.passkey_login_fallback_enabled === 'boolean'
        ? config.passkey_login_fallback_enabled
        : SYSTEM_CONFIG_DEFAULTS.passkey_login_fallback_enabled!,
  };
}

export async function getLoginPolicy(): Promise<LoginPolicy> {
  return normalizeLoginPolicy((await getSystemConfig()) as unknown as Record<string, unknown>);
}

export function isLoginMethodEnabled(policy: LoginPolicy, method: LoginMethod) {
  return policy.loginMethods.includes(method);
}

export function resolveAvailableLoginMethods({
  policy,
  user,
  hasPasskeyCredential,
  passkeyAvailable,
}: {
  policy: LoginPolicy;
  user: LoginMethodUser;
  hasPasskeyCredential: boolean;
  passkeyAvailable?: boolean;
}) {
  const passkeyUsable =
    passkeyAvailable !== false && hasPasskeyCredential && isLoginMethodEnabled(policy, 'passkey');

  if (passkeyUsable && !policy.passkeyFallbackEnabled) {
    return ['passkey'] satisfies LoginMethod[];
  }

  return LOGIN_METHOD_ORDER.filter((method) => {
    if (!isLoginMethodEnabled(policy, method)) {
      return false;
    }

    if (method === 'passkey') {
      return passkeyUsable;
    }

    if (method === 'magic_link' || method === 'email_otp') {
      return hasValue(user.email);
    }

    if (method === 'oauth') {
      return false;
    }

    return hasValue(user.phone);
  });
}
