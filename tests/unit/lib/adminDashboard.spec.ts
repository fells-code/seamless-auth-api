import express, { Express } from 'express';
import fs from 'fs';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_DASHBOARD_BASE_PATH,
  isAdminDashboardEnabled,
  mountAdminDashboard,
  resolveAdminDashboardDir,
} from '../../../src/lib/adminDashboard.js';

const INDEX_HTML = '<!doctype html><html><body><div id="root"></div></body></html>';
const ASSET_JS = 'console.log("dashboard");';

let buildDir: string;
const originalEnv = { ...process.env };

function writeBuild(dir: string) {
  fs.mkdirSync(path.join(dir, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'index.html'), INDEX_HTML);
  fs.writeFileSync(path.join(dir, 'assets', 'app-abc123.js'), ASSET_JS);
}

function buildApp(): Express {
  const app = express();
  // A stand-in for the admin API routes, registered first so we can prove the API keeps
  // priority over the SPA fallback on reserved paths.
  app.get('/admin/users', (_req, res) => {
    res.status(200).json({ source: 'api' });
  });
  mountAdminDashboard(app);
  app.use((_req, res) => res.status(404).json({ error: 'Not Found' }));
  return app;
}

beforeEach(() => {
  buildDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-dash-'));
  process.env.ADMIN_DASHBOARD_DIR = buildDir;
  delete process.env.SERVE_ADMIN_DASHBOARD;
});

afterEach(() => {
  fs.rmSync(buildDir, { recursive: true, force: true });
  process.env = { ...originalEnv };
});

describe('isAdminDashboardEnabled', () => {
  it('defaults to enabled', () => {
    delete process.env.SERVE_ADMIN_DASHBOARD;
    expect(isAdminDashboardEnabled()).toBe(true);
  });

  it('is disabled only for an explicit "false"', () => {
    process.env.SERVE_ADMIN_DASHBOARD = 'false';
    expect(isAdminDashboardEnabled()).toBe(false);

    process.env.SERVE_ADMIN_DASHBOARD = 'true';
    expect(isAdminDashboardEnabled()).toBe(true);
  });
});

describe('resolveAdminDashboardDir', () => {
  it('prefers ADMIN_DASHBOARD_DIR when set', () => {
    process.env.ADMIN_DASHBOARD_DIR = '/somewhere/custom';
    expect(resolveAdminDashboardDir()).toBe('/somewhere/custom');
  });

  it('falls back to a path relative to the bundle', () => {
    delete process.env.ADMIN_DASHBOARD_DIR;
    expect(resolveAdminDashboardDir()).toMatch(/admin-dashboard$/);
  });
});

describe('mountAdminDashboard', () => {
  it('serves index.html for the /admin root', async () => {
    writeBuild(buildDir);
    const res = await request(buildApp()).get(ADMIN_DASHBOARD_BASE_PATH);

    expect(res.status).toBe(200);
    expect(res.text).toContain('id="root"');
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('serves index.html for a deep SPA route (history fallback)', async () => {
    writeBuild(buildDir);
    const res = await request(buildApp()).get('/admin/settings/profile');

    expect(res.status).toBe(200);
    expect(res.text).toContain('id="root"');
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('serves hashed assets with an immutable long cache and correct MIME', async () => {
    writeBuild(buildDir);
    const res = await request(buildApp()).get('/admin/assets/app-abc123.js');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/javascript/);
    expect(res.headers['cache-control']).toBe('public, max-age=31536000, immutable');
  });

  it('lets the API keep priority on reserved paths', async () => {
    writeBuild(buildDir);
    const res = await request(buildApp()).get('/admin/users');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ source: 'api' });
  });

  it('404s a missing asset instead of serving index.html', async () => {
    writeBuild(buildDir);
    const res = await request(buildApp()).get('/admin/assets/missing.js');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not Found' });
  });

  it('no-ops and returns false when disabled', async () => {
    writeBuild(buildDir);
    process.env.SERVE_ADMIN_DASHBOARD = 'false';

    const app = express();
    expect(mountAdminDashboard(app)).toBe(false);
    app.use((_req, res) => res.status(404).json({ error: 'Not Found' }));

    const res = await request(app).get(ADMIN_DASHBOARD_BASE_PATH);
    expect(res.status).toBe(404);
  });

  it('no-ops and returns false when no build is present', async () => {
    // buildDir exists but has no index.html.
    const app = express();
    expect(mountAdminDashboard(app)).toBe(false);
    app.use((_req, res) => res.status(404).json({ error: 'Not Found' }));

    const res = await request(app).get(ADMIN_DASHBOARD_BASE_PATH);
    expect(res.status).toBe(404);
  });

  it('returns true when it mounts the SPA', () => {
    writeBuild(buildDir);
    expect(mountAdminDashboard(express())).toBe(true);
  });
});
