import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import express from 'express';
import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';

import { AdapterManifest, getAdapterManifest } from '../../../src/lib/adapterManifest';
import { loadRoutes } from '../../../src/lib/loadRoutes';
import { AdapterManifestSchema } from '../../../src/schemas/adapterManifest.responses';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../..');

let manifest: AdapterManifest;
let app: express.Express;

function route(method: string, path: string) {
  return manifest.routes.find((entry) => entry.method === method && entry.path === path);
}

beforeAll(async () => {
  app = express();
  await loadRoutes(app);
  manifest = getAdapterManifest();
});

describe('adapter manifest for the live routes', () => {
  it('is served at the well-known path in the published shape', async () => {
    const res = await request(app).get('/.well-known/seamless-adapter.json');

    expect(res.status).toBe(200);
    expect(AdapterManifestSchema.parse(res.body)).toEqual(manifest);
  });

  it('matches the committed adapter-manifest.json', () => {
    const committed = JSON.parse(readFileSync(join(repoRoot, 'adapter-manifest.json'), 'utf8'));

    // The version tracks package.json, which Changesets bumps without regenerating.
    expect({ ...manifest, apiVersion: undefined }).toEqual({ ...committed, apiVersion: undefined });
  });

  it('exposes none of the operational or conformance surfaces', () => {
    const hidden = manifest.routes.filter((entry) =>
      /^\/(health|conformance|\.well-known)\b/.test(entry.path),
    );

    expect(hidden).toEqual([]);
  });

  // A GET is sent cross-site without a CORS preflight, so a route that sends a message
  // must only reach adapters as POST.
  it('marks every message-sending route and exposes each as POST', () => {
    const delivery = manifest.routes.filter((entry) => entry.delivery);

    expect(delivery.map((entry) => `${entry.method} ${entry.path}`).sort()).toEqual([
      'POST /magic-link',
      'POST /otp/generate-email-otp',
      'POST /otp/generate-login-email-otp',
      'POST /otp/generate-login-phone-otp',
      'POST /otp/generate-phone-otp',
      'POST /registration/phone',
      'POST /registration/register',
    ]);
  });

  it('lists every route that issues a session', () => {
    const issuing = manifest.routes
      .filter((entry) => entry.issues)
      .map((entry) => `${entry.method} ${entry.path} ${entry.credential} -> ${entry.issues}`)
      .sort();

    expect(issuing).toEqual([
      'GET /magic-link/check preAuth -> session',
      'POST /login none -> preAuth',
      'POST /oauth/{providerId}/callback none -> session',
      'POST /organizations/{organizationId}/switch access -> access',
      'POST /otp/verify-email-otp registration -> session',
      'POST /otp/verify-login-email-otp preAuth -> session',
      'POST /otp/verify-login-phone-otp preAuth -> session',
      'POST /otp/verify-phone-otp registration -> session',
      'POST /refresh refresh -> session',
      'POST /registration/register none -> registration',
      'POST /totp/verify-login preAuth -> session',
      'POST /webauthn/login/finish preAuth -> session',
    ]);
  });

  it('keeps /login narrowed to the fields the sign-in screen reads', () => {
    expect(route('POST', '/login')?.body).toEqual({
      pick: ['message', 'identifierType', 'loginMethods'],
    });
  });

  it('clears every held token on sign-out and account deletion', () => {
    for (const path of ['/logout', '/logout/all', '/users/delete']) {
      expect(route('DELETE', path)?.clears).toEqual(['access', 'registration', 'refresh']);
    }
  });
});
