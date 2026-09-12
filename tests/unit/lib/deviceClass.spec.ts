import { describe, expect, it } from 'vitest';

import { classifyDeviceClass, DEVICE_CLASSES } from '../../../src/lib/deviceClass.js';

const UA = {
  iphone:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  ipad: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  android:
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
  mac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  windows:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  linux: 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
  chromeos:
    'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
};

describe('classifyDeviceClass', () => {
  it.each([
    ['ios', UA.iphone],
    ['ios', UA.ipad],
    ['android', UA.android],
    ['macos', UA.mac],
    ['windows', UA.windows],
    ['linux', UA.linux],
    ['chromeos', UA.chromeos],
  ])('classifies %s', (expected, userAgent) => {
    expect(classifyDeviceClass(userAgent)).toBe(expected);
  });

  // "like Mac OS X", "Linux" and "X11" all appear inside more specific platforms.
  it('does not let a broader platform token win over the specific one', () => {
    expect(classifyDeviceClass(UA.iphone)).not.toBe('macos');
    expect(classifyDeviceClass(UA.android)).not.toBe('linux');
    expect(classifyDeviceClass(UA.chromeos)).not.toBe('linux');
  });

  it.each([
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'curl/8.4.0',
    'python-requests/2.31.0',
    'Go-http-client/1.1',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36',
  ])('classifies a scanner as bot: %s', (userAgent) => {
    expect(classifyDeviceClass(userAgent)).toBe('bot');
  });

  // A server adapter calling on a browser's behalf without forwarding its user agent
  // is not a bot, and must not be counted as one.
  it('classifies a server runtime and a missing user agent as unknown', () => {
    expect(classifyDeviceClass('node')).toBe('unknown');
    expect(classifyDeviceClass('undici')).toBe('unknown');
    expect(classifyDeviceClass('unknown')).toBe('unknown');
    expect(classifyDeviceClass('')).toBe('unknown');
    expect(classifyDeviceClass(null)).toBe('unknown');
    expect(classifyDeviceClass(undefined)).toBe('unknown');
  });

  it('only ever answers with a listed class', () => {
    for (const userAgent of [...Object.values(UA), 'curl/8', 'node', '']) {
      expect(DEVICE_CLASSES).toContain(classifyDeviceClass(userAgent));
    }
  });
});
