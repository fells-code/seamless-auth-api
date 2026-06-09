import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const routesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../src/routes');
const routeCallPattern =
  /\w+Router\.(get|post|patch|put|delete)\(\s*(["'])([^"']+)\2([\s\S]*?)\n\);/g;

describe('route response schema coverage', () => {
  it('keeps protected routes wired through defineRoute auth metadata', () => {
    const manualAuthRoutes: string[] = [];

    for (const fileName of readdirSync(routesDir)
      .filter((name) => name.endsWith('.ts'))
      .sort()) {
      const source = readFileSync(join(routesDir, fileName), 'utf8');

      if (/\battachAuthMiddleware\b/.test(source)) {
        manualAuthRoutes.push(fileName);
      }
    }

    expect(manualAuthRoutes).toEqual([]);
  });

  it('documents every route with an explicit response schema', () => {
    const missingResponses: string[] = [];

    for (const fileName of readdirSync(routesDir)
      .filter((name) => name.endsWith('.ts'))
      .sort()) {
      const source = readFileSync(join(routesDir, fileName), 'utf8');
      let match: RegExpExecArray | null;

      while ((match = routeCallPattern.exec(source))) {
        const [, method, , routePath, routeDefinition] = match;

        if (!/response\s*:/.test(routeDefinition)) {
          missingResponses.push(`${fileName}: ${method.toUpperCase()} ${routePath}`);
        }
      }
    }

    expect(missingResponses).toEqual([]);
  });
});
