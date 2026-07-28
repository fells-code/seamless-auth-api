/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

// Shared by the running app (src/models/index.ts) and by sequelize-cli through
// config.cjs, so migrations and the app always agree on connectivity and TLS.

const { readFileSync } = require('fs');

const SSL_DISABLED = new Set(['false', '0', 'no', 'off', 'disable']);
const SSL_ENABLED = new Set(['true', '1', 'yes', 'on', 'require', 'prefer', 'allow']);
const SSL_VERIFIED = new Set(['verify-ca', 'verify-full']);

function resolveDatabaseUrl() {
  const { DATABASE_URL, DB_URI, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD } = process.env;

  if (DATABASE_URL) return DATABASE_URL;
  if (DB_URI) return DB_URI;

  if (!DB_HOST || !DB_PORT || !DB_NAME || !DB_USER) {
    return null;
  }

  const encodedDbUser = encodeURIComponent(DB_USER);
  const encodedDbPassword = encodeURIComponent(DB_PASSWORD ?? '');

  return `postgres://${encodedDbUser}:${encodedDbPassword}@${DB_HOST}:${DB_PORT}/${DB_NAME}`;
}

function buildDatabaseUrl() {
  const url = resolveDatabaseUrl();

  if (!url) {
    throw new Error('Missing required DB environment variables.');
  }

  return url;
}

function parseDatabaseUrl(url) {
  try {
    const parsed = new URL(url);
    const database = decodeURIComponent(parsed.pathname.replace(/^\//, ''));

    if (!parsed.hostname || !database) return null;

    return {
      host: parsed.hostname,
      port: parsed.port || undefined,
      database,
      username: parsed.username ? decodeURIComponent(parsed.username) : undefined,
      password: parsed.password ? decodeURIComponent(parsed.password) : undefined,
    };
  } catch {
    return null;
  }
}

function sslModeFromUrl(url) {
  if (!url) return null;

  const query = url.indexOf('?');
  if (query === -1) return null;

  return new URLSearchParams(url.slice(query + 1)).get('sslmode');
}

function readCertificateAuthority() {
  const value = process.env.DB_SSL_CA;

  if (!value) return null;
  if (value.includes('-----BEGIN')) return value;

  return readFileSync(value, 'utf8');
}

function isFalsy(value) {
  return SSL_DISABLED.has(value.trim().toLowerCase());
}

// Returns the `ssl` value for Sequelize's `dialectOptions`, or null to leave TLS off.
// `DB_SSL` wins over an `sslmode` carried on the connection string.
function resolveSslOptions(url) {
  const mode = (process.env.DB_SSL ?? sslModeFromUrl(url) ?? '').trim().toLowerCase();

  if (!mode || SSL_DISABLED.has(mode)) return null;

  const verifies = SSL_VERIFIED.has(mode);

  if (!verifies && !SSL_ENABLED.has(mode)) {
    throw new Error(`Unsupported DB SSL mode: ${mode}`);
  }

  const ca = readCertificateAuthority();
  const override = process.env.DB_SSL_REJECT_UNAUTHORIZED;

  // Plain `require` encrypts without verifying the server certificate, matching libpq.
  // A supplied CA bundle or a verify-* mode turns verification on.
  const rejectUnauthorized = override ? !isFalsy(override) : verifies || ca !== null;

  return ca ? { ca, rejectUnauthorized } : { rejectUnauthorized };
}

module.exports = {
  buildDatabaseUrl,
  parseDatabaseUrl,
  resolveDatabaseUrl,
  resolveSslOptions,
};
