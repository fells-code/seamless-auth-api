/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { BlockList, isIP } from 'node:net';

export const nonPublic = new BlockList();
nonPublic.addSubnet('0.0.0.0', 8, 'ipv4');
nonPublic.addSubnet('10.0.0.0', 8, 'ipv4');
nonPublic.addSubnet('100.64.0.0', 10, 'ipv4');
nonPublic.addSubnet('127.0.0.0', 8, 'ipv4');
nonPublic.addSubnet('169.254.0.0', 16, 'ipv4');
nonPublic.addSubnet('172.16.0.0', 12, 'ipv4');
nonPublic.addSubnet('192.0.0.0', 24, 'ipv4');
nonPublic.addSubnet('192.168.0.0', 16, 'ipv4');
nonPublic.addSubnet('198.18.0.0', 15, 'ipv4');
nonPublic.addSubnet('224.0.0.0', 3, 'ipv4');
nonPublic.addAddress('::', 'ipv6');
nonPublic.addAddress('::1', 'ipv6');
nonPublic.addSubnet('64:ff9b:1::', 48, 'ipv6');
nonPublic.addSubnet('fc00::', 7, 'ipv6');
nonPublic.addSubnet('fe80::', 10, 'ipv6');
nonPublic.addSubnet('ff00::', 8, 'ipv6');

// Never reachable, even for an allowlisted host: link-local carries cloud instance
// metadata, and the unspecified address means this machine.
export const neverReachable = new BlockList();
neverReachable.addSubnet('0.0.0.0', 8, 'ipv4');
neverReachable.addSubnet('169.254.0.0', 16, 'ipv4');
neverReachable.addAddress('::', 'ipv6');
neverReachable.addSubnet('fe80::', 10, 'ipv6');

export function unmapIPv4(address: string) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  return mapped ? mapped[1] : address;
}

function ipv6Hextets(address: string): number[] | null {
  let text = address;
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number);
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  const [head, tail] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const fill = text.includes('::') ? 8 - left.length - right.length : 0;
  const parts = [...left, ...Array<string>(fill).fill('0'), ...right].map((part) =>
    parseInt(part, 16),
  );

  return parts.length === 8 && parts.every((part) => part >= 0 && part <= 0xffff) ? parts : null;
}

/**
 * The IPv4 address an IPv6 address carries, for the forms a gateway turns back into
 * IPv4: IPv4-mapped and IPv4-compatible, NAT64 (64:ff9b::/96) and 6to4 (2002::/16).
 * Classifying only the IPv6 form would let `[64:ff9b::a9fe:a9fe]` reach 169.254.169.254
 * through a NAT64 gateway.
 */
function embeddedIPv4(address: string): string | null {
  const h = ipv6Hextets(address);
  if (!h) return null;

  const quad = (high: number, low: number) =>
    `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
  const zeros = (from: number, to: number) => h.slice(from, to).every((part) => part === 0);

  if (zeros(0, 5) && h[5] === 0xffff) return quad(h[6], h[7]);
  if (zeros(0, 6) && (h[6] !== 0 || h[7] > 1)) return quad(h[6], h[7]);
  if (h[0] === 0x64 && h[1] === 0xff9b && zeros(2, 6)) return quad(h[6], h[7]);
  if (h[0] === 0x2002) return quad(h[1], h[2]);

  return null;
}

export function inList(list: BlockList, address: string) {
  const plain = unmapIPv4(address.replace(/^\[|\]$/g, ''));
  const version = isIP(plain);
  if (!version) return false;
  if (version === 4) return list.check(plain, 'ipv4');

  const carried = embeddedIPv4(plain);
  return list.check(plain, 'ipv6') || (carried !== null && list.check(carried, 'ipv4'));
}
