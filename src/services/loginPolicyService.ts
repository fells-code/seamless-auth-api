/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { getSystemConfig } from '../config/getSystemConfig.js';
import { SYSTEM_CONFIG_DEFAULTS } from '../config/systemConfig.defaults.js';
import { Credential } from '../models/credentials.js';
import { LoginMethodSchema } from '../schemas/systemConfig.schema.js';

export type LoginMethod = 'passkey' | 'magic_link' | 'email_otp' | 'phone_otp' | 'oauth';

export interface LoginPolicy {
  loginMethods: LoginMethod[];
  passkeyFallbackEnabled: boolean;
  phishingResistantOnly: boolean;
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

  // Strictly true, so a malformed value leaves the mode off the way the schema default
  // would rather than turning it on by accident.
  if (config?.phishing_resistant_only === true) {
    return {
      loginMethods: ['passkey'] satisfies LoginMethod[],
      passkeyFallbackEnabled: false,
      phishingResistantOnly: true,
    };
  }

  return {
    loginMethods: loginMethods.length
      ? loginMethods
      : (SYSTEM_CONFIG_DEFAULTS.login_methods as LoginMethod[]),
    passkeyFallbackEnabled:
      typeof config?.passkey_login_fallback_enabled === 'boolean'
        ? config.passkey_login_fallback_enabled
        : SYSTEM_CONFIG_DEFAULTS.passkey_login_fallback_enabled!,
    phishingResistantOnly: false,
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
  // What the deployment permits, which is policy plus whether the account has a
  // passkey at all. Deliberately excludes passkeyAvailable: that is the client
  // describing itself, and a caller does not get to choose how strongly it
  // authenticates.
  const passkeyPermitted = hasPasskeyCredential && isLoginMethodEnabled(policy, 'passkey');

  // Passkey-only, so the hint cannot add a weaker method here. A client that
  // genuinely cannot run the ceremony fails at it, which is what this setting
  // means: the alternative offers email OTP to anyone who claims not to support
  // passkeys, which is the whole guarantee gone for the cost of one request field.
  if (passkeyPermitted && !policy.passkeyFallbackEnabled) {
    return ['passkey'] satisfies LoginMethod[];
  }

  // Fallback is allowed, so the hint does its real job: drop a method the client
  // has said it cannot complete, from a set the policy already permits.
  const passkeyUsable = passkeyPermitted && passkeyAvailable !== false;

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

/**
 * Whether a sign-in has to be a passkey, whatever other method the deployment enables.
 * True in phishing-resistant-only mode, and for an account holding a passkey when
 * fallback is off.
 *
 * The continuation endpoints check this as well as the method list. `/login` already
 * leaves a fallback out of what it offers such an account, but the fallback's endpoint
 * was still callable directly with the ephemeral token `/login` handed out.
 */
export function isPasskeyRequired(policy: LoginPolicy, hasPasskeyCredential: boolean) {
  if (policy.phishingResistantOnly) return true;

  return (
    hasPasskeyCredential &&
    !policy.passkeyFallbackEnabled &&
    isLoginMethodEnabled(policy, 'passkey')
  );
}

export async function isPasskeyRequiredForUser(userId: string, policy?: LoginPolicy) {
  const resolvedPolicy = policy ?? (await getLoginPolicy());

  // Settled without a query whenever the answer does not depend on the account.
  if (resolvedPolicy.phishingResistantOnly) return true;
  if (!isPasskeyRequired(resolvedPolicy, true)) return false;

  return isPasskeyRequired(resolvedPolicy, (await Credential.count({ where: { userId } })) > 0);
}
