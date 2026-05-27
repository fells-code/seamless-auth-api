/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { redactMetadata } from '../utils/redaction.js';

export function serializeAuthEvent(event: unknown) {
  const raw =
    event && typeof event === 'object' && 'toJSON' in event && typeof event.toJSON === 'function'
      ? event.toJSON()
      : event;

  if (!raw || typeof raw !== 'object') {
    return raw;
  }

  const serialized = raw as Record<string, unknown>;

  return {
    ...serialized,
    metadata: redactMetadata(serialized.metadata as Record<string, unknown> | null | undefined),
  };
}

export function serializeAuthEvents(events: unknown[]) {
  return events.map(serializeAuthEvent);
}
