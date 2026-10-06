/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import crypto from 'crypto';
import parsePhoneNumberFromString from 'libphonenumber-js';
import validator from 'validator';

export const isValidEmail = (email: string): boolean => {
  return validator.isEmail(email);
};

export const isValidPhoneNumber = (phone: string): boolean => {
  const phoneNumber = parsePhoneNumberFromString(phone);
  return phoneNumber?.isValid() || false;
};

export const normalizePhoneNumber = (phone: string): string | null => {
  const phoneNumber = parsePhoneNumberFromString(phone);

  if (!phoneNumber?.isValid()) {
    return null;
  }

  return phoneNumber.number;
};

export interface SessionTtls {
  /** Absolute session lifetime. The refresh token is the session credential, so this is `refresh_token_ttl`. */
  absoluteTtl: string;
  /** How long the session may go unrefreshed. Only binds while it is the shorter of the two. */
  idleTtl: string;
}

export function computeSessionTimes({ absoluteTtl, idleTtl }: SessionTtls, now = new Date()) {
  const expiresAt = new Date(now.getTime() + parseDurationToSeconds(absoluteTtl) * 1000);
  const idleExpiresAt = new Date(now.getTime() + parseDurationToSeconds(idleTtl) * 1000);
  return { expiresAt, idleExpiresAt };
}

/**
 * Times for the session a refresh rotates into. The absolute bound is measured from the
 * start of the rotation chain, so refreshing cannot extend a session past it, while the
 * idle bound slides from `now` and never reaches past the absolute one.
 */
export function computeRotatedSessionTimes(
  { absoluteTtl, idleTtl }: SessionTtls,
  chainStartedAt: Date,
  now = new Date(),
) {
  const expiresAt = new Date(chainStartedAt.getTime() + parseDurationToSeconds(absoluteTtl) * 1000);
  const slidingIdle = now.getTime() + parseDurationToSeconds(idleTtl) * 1000;
  const idleExpiresAt = new Date(Math.min(slidingIdle, expiresAt.getTime()));
  return { expiresAt, idleExpiresAt };
}

export function parseDurationToSeconds(input: string): number {
  if (!input || typeof input !== 'string') {
    throw new Error('Invalid duration string');
  }

  const regex = /^(\d+)(s|m|h|d|w)$/i;
  const match = input.trim().match(regex);

  if (!match) {
    throw new Error(`Invalid duration format: ${input}`);
  }

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();

  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 60 * 60,
    d: 60 * 60 * 24,
    w: 60 * 60 * 24 * 7,
  };

  return value * multipliers[unit];
}

export function hashSha256(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function hashDeviceFingerprint(ip?: string, userAgent?: string) {
  return {
    ip_hash: ip ? hashSha256(ip) : null,
    user_agent_hash: userAgent ? hashSha256(userAgent) : null,
  };
}
