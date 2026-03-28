/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

export function expressToOpenAPI(path: string): string {
  return path.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}
