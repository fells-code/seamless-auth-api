/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { OpenApiGeneratorV3 } from '@asteasolutions/zod-to-openapi';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { registry } from './registry.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * The published version, read once.
 *
 * It cannot change while the process runs, and it backs `/health/version`, which
 * takes no authentication, so reading it per request put a synchronous file read and
 * a parse on the event loop for every caller. Resolved from this module rather than
 * `process.cwd()`, which is not the repository root for a process started elsewhere.
 */
let packageVersion: string | undefined;

export function getPackageVersion(): string {
  if (packageVersion !== undefined) {
    return packageVersion;
  }

  try {
    const pkgPath = path.resolve(__dirname, '../../package.json');
    packageVersion = (JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version as string) ?? '0.0.0';
  } catch {
    packageVersion = '0.0.0';
  }

  return packageVersion;
}

export function generateOpenApiDocument() {
  const generator = new OpenApiGeneratorV3(registry.definitions);

  const document = generator.generateDocument({
    openapi: '3.0.3',
    info: {
      title: 'Seamless Auth API',
      version: getPackageVersion(),
    },
  });

  document.components = {
    ...document.components,
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
  };

  return document;
}
