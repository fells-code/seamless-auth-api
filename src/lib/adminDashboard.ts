/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import express, { Express, NextFunction, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import getLogger from '../utils/logger.js';

const logger = getLogger('adminDashboard');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ADMIN_DASHBOARD_BASE_PATH = '/admin';

// The dashboard SPA shares the /admin namespace with the admin API routes. Those API
// routes are registered before this static handler and therefore keep priority; the
// SPA only ever serves paths the API leaves unmatched. A hard refresh on one of these
// reserved sub-paths hits the API, so the dashboard's same-origin build must keep its
// client route paths out of this set. Kept in sync with src/routes/admin.routes.ts.
const RESERVED_API_SEGMENTS = new Set([
  'organizations',
  'users',
  'sessions',
  'audit-events',
  'credential-count',
]);

export function isAdminDashboardEnabled(): boolean {
  // Default enabled for managed instances; disable only with an explicit "false".
  return process.env.SERVE_ADMIN_DASHBOARD !== 'false';
}

export function resolveAdminDashboardDir(): string {
  return process.env.ADMIN_DASHBOARD_DIR ?? path.resolve(__dirname, '../../admin-dashboard');
}

/**
 * Mounts static serving for the admin dashboard SPA under /admin when enabled and a build
 * is present. Additive only: it never intercepts an existing API route, and it no-ops
 * (leaving the API fully functional) when the flag is off or no build was bundled.
 * Returns true when the SPA was mounted.
 */
export function mountAdminDashboard(app: Express): boolean {
  if (!isAdminDashboardEnabled()) {
    logger.info('Admin dashboard serving disabled (SERVE_ADMIN_DASHBOARD=false).');
    return false;
  }

  const dir = resolveAdminDashboardDir();
  const indexHtml = path.join(dir, 'index.html');

  if (!fs.existsSync(indexHtml)) {
    logger.warn(
      `Admin dashboard enabled but no build found at ${dir}. Skipping static serving. ` +
        'Ship the dashboard build into the image or set SERVE_ADMIN_DASHBOARD=false to silence this.',
    );
    return false;
  }

  const staticHandler = express.static(dir, {
    index: false,
    // Let the history fallback below own the /admin root instead of a 301 to /admin/.
    redirect: false,
    setHeaders: (res, filePath) => {
      if (path.basename(filePath) === 'index.html') {
        res.setHeader('Cache-Control', 'no-store');
      } else if (filePath.includes(`${path.sep}assets${path.sep}`)) {
        // Vite emits content-hashed asset filenames, so they are safe to cache forever.
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      }
    },
  });

  app.use(ADMIN_DASHBOARD_BASE_PATH, staticHandler);

  const sendIndex = (req: Request, res: Response, next: NextFunction) => {
    // A request for a missing file (has an extension) should 404 normally rather than
    // receive index.html with the wrong MIME type.
    if (path.extname(req.path)) {
      return next();
    }
    res.setHeader('Cache-Control', 'no-store');
    return res.sendFile(indexHtml, (err) => {
      if (err) {
        next(err);
      }
    });
  };

  app.get(ADMIN_DASHBOARD_BASE_PATH, sendIndex);
  app.get(`${ADMIN_DASHBOARD_BASE_PATH}/*`, sendIndex);

  const reserved = [...RESERVED_API_SEGMENTS].map((s) => `/admin/${s}`).join(', ');
  logger.info(
    `Serving admin dashboard at ${ADMIN_DASHBOARD_BASE_PATH} from ${dir}. ` +
      `API keeps priority on reserved paths (${reserved}).`,
  );
  return true;
}
