/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 */
import parsePhoneNumberFromString from 'libphonenumber-js';
import validator from 'validator';

const MAX_SESSION_LIFETIME_DAYS = 1;
const IDLE_TIMEOUT_DAYS = 1;

export const isValidEmail = (email: string): boolean => {
  return validator.isEmail(email);
};

export const isValidPhoneNumber = (phone: string): boolean => {
  const phoneNumber = parsePhoneNumberFromString(phone);
  return phoneNumber?.isValid() || false;
};

export function computeSessionTimes(now = new Date()) {
  const expiresAt = new Date(now.getTime() + MAX_SESSION_LIFETIME_DAYS * 24 * 60 * 60 * 1000);
  const idleExpiresAt = new Date(now.getTime() + IDLE_TIMEOUT_DAYS * 24 * 60 * 60 * 1000);
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
