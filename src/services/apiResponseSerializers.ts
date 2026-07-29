/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { type Transport, TransportSchema } from '@seamless-auth/types';

type SerializableRecord = Record<string, unknown>;

function isRecord(value: unknown): value is SerializableRecord {
  return Boolean(value && typeof value === 'object');
}

function readField(source: unknown, key: string): unknown {
  if (!isRecord(source)) return undefined;

  const direct = source[key];
  if (direct !== undefined) return direct;

  const get = source.get;
  if (typeof get === 'function') {
    try {
      const plain = get.call(source, { plain: true });
      if (isRecord(plain)) return plain[key];
    } catch {
      // Fall back to direct object fields below.
    }
  }

  return undefined;
}

function stringField(source: unknown, key: string): string {
  const value = readField(source, key);
  return typeof value === 'string' ? value : String(value ?? '');
}

function nullableStringField(source: unknown, key: string): string | null | undefined {
  const value = readField(source, key);
  if (value === undefined) return undefined;
  if (value === null) return null;
  return typeof value === 'string' ? value : String(value);
}

function booleanField(source: unknown, key: string): boolean | undefined {
  const value = readField(source, key);
  return typeof value === 'boolean' ? value : undefined;
}

function numberField(source: unknown, key: string, fallback = 0): number {
  const value = readField(source, key);
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }

  return fallback;
}

function dateField(source: unknown, key: string): string | null | undefined {
  const value = readField(source, key);
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'string') return value;
  if (typeof value === 'number') {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
  }

  return undefined;
}

function stringArrayField(source: unknown, key: string): string[] {
  const value = readField(source, key);
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function optionalStringArrayField(source: unknown, key: string): string[] | undefined {
  const value = readField(source, key);
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function credentialDeviceTypeField(
  credential: unknown,
): 'singleDevice' | 'multiDevice' | undefined {
  const value = readField(credential, 'deviceType');
  return value === 'singleDevice' || value === 'multiDevice' ? value : undefined;
}

function transportField(credential: unknown): Transport[] | undefined {
  const transports = optionalStringArrayField(credential, 'transports');
  if (transports === undefined) return undefined;

  // Filtered against the shared transport set so a malformed stored value cannot break
  // a response, while hybrid, cable, and smart-card all survive.
  return transports.filter(
    (transport): transport is Transport => TransportSchema.safeParse(transport).success,
  );
}

function omitUndefined<T extends SerializableRecord>(value: T) {
  return Object.fromEntries(
    Object.entries(value).filter(([, fieldValue]) => fieldValue !== undefined),
  ) as T;
}

export function serializeApiUser(user: unknown) {
  return omitUndefined({
    id: stringField(user, 'id'),
    email: stringField(user, 'email'),
    phone: nullableStringField(user, 'phone') ?? null,
    roles: stringArrayField(user, 'roles'),
    revoked: booleanField(user, 'revoked'),
    emailVerified: booleanField(user, 'emailVerified'),
    phoneVerified: booleanField(user, 'phoneVerified'),
    verified: booleanField(user, 'verified'),
    lastLogin: dateField(user, 'lastLogin'),
    createdAt: dateField(user, 'createdAt'),
    updatedAt: dateField(user, 'updatedAt'),
  });
}

export function serializeCredential(credential: unknown) {
  const backedUp =
    booleanField(credential, 'backedUp') ?? booleanField(credential, 'backedup') ?? false;

  return omitUndefined({
    id: stringField(credential, 'id'),
    transports: transportField(credential),
    deviceType: credentialDeviceTypeField(credential),
    backedup: backedUp,
    backedUp,
    counter: numberField(credential, 'counter'),
    prfCapable: booleanField(credential, 'prfCapable'),
    friendlyName: nullableStringField(credential, 'friendlyName'),
    lastUsedAt: dateField(credential, 'lastUsedAt'),
    platform: nullableStringField(credential, 'platform'),
    browser: nullableStringField(credential, 'browser'),
    deviceInfo: nullableStringField(credential, 'deviceInfo'),
    createdAt: dateField(credential, 'createdAt'),
  });
}

export function serializeSession(session: unknown, currentSessionId?: string | null) {
  const id = stringField(session, 'id');

  return omitUndefined({
    id,
    deviceName: nullableStringField(session, 'deviceName'),
    ipAddress: nullableStringField(session, 'ipAddress'),
    userAgent: nullableStringField(session, 'userAgent'),
    lastUsedAt: dateField(session, 'lastUsedAt'),
    expiresAt: dateField(session, 'expiresAt'),
    current: currentSessionId ? id === currentSessionId : false,
  });
}
