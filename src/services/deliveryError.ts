/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * A code or link could not be handed to the provider.
 *
 * Distinguished from everything else that can go wrong around a send (the OTP row
 * not saving, say) so callers can record it as a delivery failure against the
 * recipient's provider rather than as a server fault.
 */
export class DeliveryError extends Error {
  constructor(context: string, cause: unknown) {
    super(`${context}: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    this.name = 'DeliveryError';
  }
}
