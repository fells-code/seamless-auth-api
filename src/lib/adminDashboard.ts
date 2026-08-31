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

// Served under /console rather than /admin so the SPA namespace never overlaps the admin
// API routes (which live under /admin/*). The handler is still registered after the API
// routers, so the API keeps priority regardless.
export const ADMIN_DASHBOARD_BASE_PATH = '/console';

export function isAdminDashboardEnabled(): boolean {
  // Default enabled for managed instances; disable only with an explicit "false".
  return process.env.SERVE_ADMIN_DASHBOARD !== 'false';
}

export function resolveAdminDashboardDir(): string {
  return process.env.ADMIN_DASHBOARD_DIR ?? path.resolve(__dirname, '../../admin-dashboard');
}

/**
 * Mounts static serving for the admin dashboard SPA under /console when enabled and a build
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
    // Let the history fallback below own the /console root instead of a 301 to /console/.
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
  // Named wildcard: path-to-regexp v8 (Express 5) rejects a bare "*".
  app.get(`${ADMIN_DASHBOARD_BASE_PATH}/*splat`, sendIndex);

  logger.info(`Serving admin dashboard at ${ADMIN_DASHBOARD_BASE_PATH} from ${dir}.`);
  return true;
}
