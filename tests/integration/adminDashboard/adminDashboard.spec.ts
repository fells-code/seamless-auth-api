import { Application } from 'express';
import fs from 'fs';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

let app: Application;
let buildDir: string;

beforeAll(async () => {
  buildDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-dash-int-'));
  fs.mkdirSync(path.join(buildDir, 'assets'), { recursive: true });
  fs.writeFileSync(
    path.join(buildDir, 'index.html'),
    '<!doctype html><html><body><div id="root"></div></body></html>',
  );
  fs.writeFileSync(path.join(buildDir, 'assets', 'app-abc123.js'), 'console.log("dash");');

  process.env.SERVE_ADMIN_DASHBOARD = 'true';
  process.env.ADMIN_DASHBOARD_DIR = buildDir;

  const { createApp } = await import('../../../src/app');
  app = await createApp();
});

afterAll(() => {
  fs.rmSync(buildDir, { recursive: true, force: true });
  delete process.env.ADMIN_DASHBOARD_DIR;
  delete process.env.SERVE_ADMIN_DASHBOARD;
});

describe('Admin dashboard static serving (via createApp)', () => {
  it('serves the SPA at /admin', async () => {
    const res = await request(app).get('/admin');
    expect(res.status).toBe(200);
    expect(res.text).toContain('id="root"');
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('serves the SPA history fallback for a deep client route', async () => {
    const res = await request(app).get('/admin/anything/here');
    expect(res.status).toBe(200);
    expect(res.text).toContain('id="root"');
  });

  it('serves hashed assets with an immutable cache header', async () => {
    const res = await request(app).get('/admin/assets/app-abc123.js');
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('public, max-age=31536000, immutable');
  });

  it('does not shadow API routes: health still resolves', async () => {
    const res = await request(app).get('/health/status');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ message: 'System up' });
  });

  it('leaves the /admin API namespace to the API (reserved path is not the SPA)', async () => {
    // /admin/users is an admin API route. It must resolve to the API (JSON), never the SPA
    // shell, proving the API keeps priority on reserved paths.
    const res = await request(app).get('/admin/users');
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.text).not.toContain('id="root"');
  });
});
