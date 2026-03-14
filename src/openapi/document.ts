import { OpenApiGeneratorV3 } from '@asteasolutions/zod-to-openapi';
import fs from 'fs';
import path from 'path';

import { registry } from './registry.js';

export function getPackageVersion(): string {
  const pkgPath = path.resolve(process.cwd(), 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  return pkg.version ?? '0.0.0';
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
      cookieAuth: {
        type: 'apiKey',
        in: 'cookie',
        name: 'access_token',
      },
    },
  };

  return document;
}
