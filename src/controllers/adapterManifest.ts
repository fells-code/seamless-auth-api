/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { Request, Response } from 'express';

import { getAdapterManifest } from '../lib/adapterManifest.js';

export function adapterManifestHandler(_req: Request, res: Response) {
  res.json(getAdapterManifest());
}
