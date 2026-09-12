/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

/**
 * The platform families a user agent is folded into for telemetry.
 *
 * Platforms rather than form factors, because platform is where passkeys differ:
 * iCloud Keychain, Google Password Manager, Windows Hello and a Linux desktop with no
 * platform authenticator at all are four different passkey experiences, and "mobile"
 * against "desktop" would hide the two that matter most. The mobile split still falls
 * out of it (iOS and Android against the rest).
 *
 * `bot` separates scanners from people so their failures do not sink a published
 * success rate. `unknown` is a missing user agent or one that names no platform, which
 * includes a server adapter calling on a browser's behalf without forwarding its user
 * agent.
 */
export const DEVICE_CLASSES = [
  'ios',
  'android',
  'macos',
  'windows',
  'linux',
  'chromeos',
  'bot',
  'unknown',
] as const;

export type DeviceClass = (typeof DEVICE_CLASSES)[number];

const BOT_PATTERN =
  /\bbot\b|bot[/\-;)]|crawler|spider|slurp|facebookexternalhit|curl\/|wget\/|python-requests|python-urllib|go-http-client|java\/|libwww|httpclient|headlesschrome|phantomjs|scrapy/i;

/**
 * Order matters. An iOS user agent says "like Mac OS X", an Android one says "Linux",
 * and a ChromeOS one says "X11", so the more specific platform is tested first.
 */
export function classifyDeviceClass(userAgent: string | null | undefined): DeviceClass {
  if (!userAgent) return 'unknown';

  if (BOT_PATTERN.test(userAgent)) return 'bot';
  if (/\b(iPhone|iPad|iPod)\b/.test(userAgent)) return 'ios';
  if (/\bAndroid\b/.test(userAgent)) return 'android';
  if (/\bCrOS\b/.test(userAgent)) return 'chromeos';
  if (/\bWindows\b/.test(userAgent)) return 'windows';
  if (/\bMacintosh\b|\bMac OS X\b/.test(userAgent)) return 'macos';
  if (/\bLinux\b|\bX11\b/.test(userAgent)) return 'linux';

  return 'unknown';
}
