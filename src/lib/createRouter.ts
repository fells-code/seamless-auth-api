/* eslint-disable @typescript-eslint/no-explicit-any */
import { Router } from 'express';

import { defineRoute } from './defineRoute.js';

export function createRouter(basePath = '', baseRouter: Router = Router()) {
  function withBase(path: string) {
    return `${basePath}${path}`;
  }

  return {
    router: baseRouter,

    get(path: string, options: Omit<any, 'method' | 'path' | 'handler'>, handler: any) {
      defineRoute(baseRouter, {
        method: 'get',
        path: withBase(path),
        ...options,
        handler,
      });
    },

    post(path: string, options: Omit<any, 'method' | 'path' | 'handler'>, handler: any) {
      defineRoute(baseRouter, {
        method: 'post',
        path: withBase(path),
        ...options,
        handler,
      });
    },

    put(path: string, options: Omit<any, 'method' | 'path' | 'handler'>, handler: any) {
      defineRoute(baseRouter, {
        method: 'put',
        path: withBase(path),
        ...options,
        handler,
      });
    },

    patch(path: string, options: Omit<any, 'method' | 'path' | 'handler'>, handler: any) {
      defineRoute(baseRouter, {
        method: 'patch',
        path: withBase(path),
        ...options,
        handler,
      });
    },

    delete(path: string, options: Omit<any, 'method' | 'path' | 'handler'>, handler: any) {
      defineRoute(baseRouter, {
        method: 'delete',
        path: withBase(path),
        ...options,
        handler,
      });
    },
  };
}
