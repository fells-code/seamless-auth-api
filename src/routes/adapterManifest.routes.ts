/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { adapterManifestHandler } from '../controllers/adapterManifest.js';
import { createRouter } from '../lib/createRouter.js';
import { AdapterManifestSchema } from '../schemas/adapterManifest.responses.js';

const adapterManifestRouter = createRouter('');

adapterManifestRouter.get(
  '/.well-known/seamless-adapter.json',
  {
    adapter: false,
    summary: 'Routes a server adapter exposes and what it does with each',
    description:
      'Server adapters load this at startup instead of hard-coding routes. It describes which ' +
      'token each route takes and which tokens a response issues or clears.',
    tags: ['Adapters'],

    schemas: {
      response: {
        200: AdapterManifestSchema,
      },
    },
  },
  adapterManifestHandler,
);

export default adapterManifestRouter.router;
