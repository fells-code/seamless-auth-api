/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the GNU Affero General Public License v3.0
 * See LICENSE file in the project root for full license information
 */

import { describe, expect, it, vi } from 'vitest';

import authRouter from '../../../src/routes/auth.routes.js';

describe('auth routes', () => {
  it('returns 405 for non-POST /refresh requests', () => {
    const refreshLayers = (authRouter as any).stack.filter(
      (layer: any) => layer.route?.path === '/refresh',
    );

    const methodNotAllowedLayer = refreshLayers.find((layer: any) => layer.route.methods._all);

    expect(methodNotAllowedLayer).toBeDefined();

    const handler = methodNotAllowedLayer.route.stack[0].handle;
    const req = {};
    const res = {
      setHeader: vi.fn(),
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };

    handler(req, res);

    expect(res.setHeader).toHaveBeenCalledWith('Allow', 'POST');
    expect(res.status).toHaveBeenCalledWith(405);
    expect(res.json).toHaveBeenCalledWith({ error: 'Method Not Allowed' });
  });
});
