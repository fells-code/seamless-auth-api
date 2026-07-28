/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

export interface DatabaseConnection {
  host: string;
  port?: string;
  database: string;
  username?: string;
  password?: string;
}

export interface DatabaseSslOptions {
  ca?: string;
  rejectUnauthorized: boolean;
}

export declare function buildDatabaseUrl(): string;
export declare function parseDatabaseUrl(url: string): DatabaseConnection | null;
export declare function resolveDatabaseUrl(): string | null;
export declare function resolveSslOptions(url: string | null): DatabaseSslOptions | null;
