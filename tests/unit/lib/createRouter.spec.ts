import { Router } from 'express';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/lib/defineRoute.js', () => ({
  defineRoute: vi.fn(),
}));

import { createRouter } from '../../../src/lib/createRouter.js';
import { defineRoute } from '../../../src/lib/defineRoute.js';

describe('createRouter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('exposes the provided base router', () => {
    const baseRouter = Router();
    const api = createRouter('/base', baseRouter);

    expect(api.router).toBe(baseRouter);
  });

  it('registers each HTTP verb with the base path prefixed and method set', () => {
    const baseRouter = Router();
    const api = createRouter('/base', baseRouter);
    const handler = vi.fn();
    const options = { summary: 'test' };

    api.get('/get', options, handler);
    api.post('/post', options, handler);
    api.put('/put', options, handler);
    api.patch('/patch', options, handler);
    api.delete('/delete', options, handler);

    const calls = (defineRoute as any).mock.calls.map(([router, def]: [unknown, any]) => [
      router,
      def.method,
      def.path,
    ]);

    expect(calls).toEqual([
      [baseRouter, 'get', '/base/get'],
      [baseRouter, 'post', '/base/post'],
      [baseRouter, 'put', '/base/put'],
      [baseRouter, 'patch', '/base/patch'],
      [baseRouter, 'delete', '/base/delete'],
    ]);

    for (const [, def] of (defineRoute as any).mock.calls) {
      expect(def.summary).toBe('test');
      expect(def.handler).toBe(handler);
    }
  });

  it('defaults to an empty base path and a fresh router when omitted', () => {
    const api = createRouter();
    const handler = vi.fn();

    api.get('/plain', {}, handler);

    expect(defineRoute).toHaveBeenCalledWith(
      api.router,
      expect.objectContaining({ method: 'get', path: '/plain', handler }),
    );
  });
});
