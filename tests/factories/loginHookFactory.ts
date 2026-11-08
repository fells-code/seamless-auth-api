import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { vi } from 'vitest';

import { encryptCalloutSecret } from '../../src/lib/calloutSigning.js';

export const testHookSecret = 'whsec_' + Buffer.alloc(32, 5).toString('base64');

export function buildLoginHook(overrides: Record<string, unknown> = {}) {
  const sealed = encryptCalloutSecret(testHookSecret);
  const now = new Date();
  const record: any = {
    trigger: 'post_login',
    url: 'http://127.0.0.1:1/hook',
    timeoutMs: 2000,
    failureMode: 'closed',
    enabled: true,
    secretCiphertext: sealed.ciphertext,
    secretIv: sealed.iv,
    secretTag: sealed.tag,
    previousSecretCiphertext: null,
    previousSecretIv: null,
    previousSecretTag: null,
    previousSecretExpiresAt: null,
    createdBy: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  record.update = vi.fn(async (values: Record<string, unknown>) => Object.assign(record, values));
  record.destroy = vi.fn();
  return record;
}

export type HookServer = {
  url: string;
  received: { headers: IncomingHttpHeaders; body: string }[];
  close: () => Promise<void>;
};

/** A real hook service on loopback, which callouts may reach outside production. */
export async function startHookServer(status: number, answer: unknown): Promise<HookServer> {
  const received: HookServer['received'] = [];
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      received.push({ headers: req.headers, body });
      res.statusCode = status;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(answer));
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}/hook`,
    received,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((done) => server.close(() => done()));
    },
  };
}
