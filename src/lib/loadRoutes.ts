import { Express, Router } from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function loadRoutes(app: Express) {
  const routesDir = path.resolve(__dirname, '../routes');

  const files = fs.readdirSync(routesDir);

  for (const file of files) {
    if (!file.endsWith('.routes.js') && !file.endsWith('.routes.ts')) {
      continue;
    }

    const modulePath = path.join(routesDir, file);

    const routeModule = await import(pathToFileURL(modulePath).href);

    const router: Router | undefined = routeModule.default;

    if (!router) {
      console.warn(`[loadRoutes] ${file} has no default router export`);
      continue;
    }

    app.use(router);
  }
}
