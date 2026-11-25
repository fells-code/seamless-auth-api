/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { QueryTypes } from 'sequelize';

import { SystemConfig as SysConfigModel } from '../models/systemConfig.js';
import { SystemConfig, SystemConfigSchema } from '../schemas/systemConfig.schema.js';
import getLogger from '../utils/logger.js';

const logger = getLogger('systemConfig');

// A write on any instance, or a direct database edit, is seen everywhere within this long.
// Under it, reads come from memory; past it, one small fingerprint query decides whether
// the cached copy is still the stored one.
export const SYSTEM_CONFIG_CHECK_INTERVAL_MS = 1_000;

// Hashes the stored content rather than reading "updatedAt": that column is written from
// each instance's own clock, so skew between replicas can make a newer write look older,
// and a direct UPDATE need not touch it at all.
const FINGERPRINT_SQL = `SELECT md5(coalesce(string_agg(key || '=' || value::text, ',' ORDER BY key), '')) AS fingerprint FROM system_config`;

let cachedConfig: SystemConfig | null = null;
let cachedFingerprint: string | null = null;
let lastCheckedAt = 0;
let generation = 0;
let inFlight: Promise<SystemConfig> | null = null;

async function readFingerprint(): Promise<string> {
  const rows = await SysConfigModel.sequelize!.query<{ fingerprint: string }>(FINGERPRINT_SQL, {
    type: QueryTypes.SELECT,
  });

  return rows[0]?.fingerprint ?? '';
}

interface Loaded {
  config: SystemConfig;
  fingerprint: string;
}

async function loadConfig(): Promise<Loaded> {
  const fingerprint = await readFingerprint();

  if (cachedConfig && fingerprint === cachedFingerprint) {
    return { config: cachedConfig, fingerprint };
  }

  // The fingerprint is read first, so a write that lands between the two reads leaves an
  // older fingerprint beside newer rows, and the next check reloads. It never pairs a
  // current fingerprint with stale rows.
  const rows = await SysConfigModel.findAll();
  const raw = Object.fromEntries(rows.map((row) => [row.key, row.value]));
  const parsed = SystemConfigSchema.safeParse(raw);

  if (!parsed.success) {
    logger.error(`Invalid system_config on runtime load: ${parsed.error.message}`);
    throw new Error('Invalid system_config: runtime configuration failed schema validation');
  }

  return { config: parsed.data, fingerprint };
}

/**
 * Fails closed: when the fingerprint query errors, the call throws rather than serve a copy
 * that can no longer be shown to be current.
 */
export async function getSystemConfig(): Promise<SystemConfig> {
  if (cachedConfig && Date.now() - lastCheckedAt < SYSTEM_CONFIG_CHECK_INTERVAL_MS) {
    return cachedConfig;
  }

  if (!inFlight) {
    const startedIn = generation;
    const startedAt = Date.now();

    inFlight = loadConfig()
      .then(({ config, fingerprint }) => {
        if (startedIn === generation) {
          cachedConfig = config;
          cachedFingerprint = fingerprint;
          lastCheckedAt = startedAt;
        }
        return config;
      })
      .finally(() => {
        if (startedIn === generation) inFlight = null;
      });
  }

  return inFlight;
}

export function invalidateSystemConfigCache() {
  generation += 1;
  cachedConfig = null;
  cachedFingerprint = null;
  lastCheckedAt = 0;
  inFlight = null;
}
